#!/usr/bin/env python3
# check_owners.py — commit-time module-ownership enforcement (find-owners format)
"""Fail a change that edits paths the author does not own.

Guardrail for multi-person AI-agent development: an agent told to fix module A
will happily "improve" module B on the way past. A prose rule in AGENTS.md is
advice; this is a check.

OWNERS files use the find-owners (Chromium) format, so the same files can later
be handed to Gerrit's find-owners submit rule without a rewrite:

    # comment
    set noparent                       # stop inheriting owners from parent dirs
    alice@example.com                  # owns this directory (and subdirs)
    per-file *_test.py = bob@example.com   # basename glob, this directory only
    *                                  # anyone may touch this directory

Supported: comments, blank lines, `set noparent`, bare owner lines, `*`,
`per-file <glob>[,<glob>] = <owner>[,<owner>|*]`.
Unsupported directives (`include`, `file:`, `per-file ... = set noparent`) raise
instead of being skipped -- silently ignoring them would change the owner set
and turn a violation into a false pass.

Trust boundary (the part an adversarial author will attack)
  * OWNERS and the exempt list are read from the **base tree** (the merge-base
    of --base and --rev), never from the change itself -- so a change cannot
    grant itself ownership or exempt itself in the same commit.
  * The changed set is `git diff <merge-base> <rev>`, so wrapping a crossing in
    a merge commit does not skip it.
  * Paths are read NUL-delimited with core.quotePath off, so non-ASCII or
    whitespace filenames cannot dodge the OWNERS lookup; anything unparseable
    fails closed (exit 2).
  * In `--mode review` the author MUST be passed via --author, taken from the
    authenticated uploader (Gerrit change owner / CI identity). The commit's
    own author field (%ae) is writable by the author and is only ever used in
    local advisory mode.

Semantics
  * `per-file` globs match the **basename**, in the OWNERS file's own directory
    only (find-owners behaviour). To scope a subdirectory, put an OWNERS file
    in it.
  * Owners accumulate from the file's directory upwards, stopping at the first
    `set noparent`.
  * A path no OWNERS file covers is **unowned and allowed** -- otherwise adding
    one OWNERS file would lock the whole repo.
  * Emails compare case-insensitively (casefold), matching how Gerrit resolves
    accounts.

The escape hatch has a lock
  `Cross-Owner: <reason>` in the commit message is a *reason*, not permission.
  In review mode the check additionally requires that, for **every** crossed
  path, one of that path's owners approved the change. Grepping for the trailer
  alone would let an agent unblock itself by writing one line.

Exit codes: 0 ok, 1 violation, 2 usage/config error.
"""
from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import PurePosixPath

ANYONE = "*"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"  # git's well-known empty tree
CROSS_OWNER_RE = re.compile(r"^Cross-Owner:\s*(\S.*)$", re.MULTILINE)
REVERT_RE = re.compile(r'^Revert "|^This reverts commit ', re.MULTILINE)


class ConfigError(Exception):
    """Malformed or unsupported OWNERS/diff content."""


@dataclass(frozen=True)
class OwnersFile:
    noparent: bool = False
    dir_owners: frozenset[str] = frozenset()
    per_file: tuple[tuple[str, frozenset[str]], ...] = ()


@dataclass(frozen=True)
class Violation:
    path: str
    owners: frozenset[str]


@dataclass(frozen=True)
class Result:
    ok: bool
    violations: tuple[Violation, ...] = ()
    messages: tuple[str, ...] = ()


def _norm(email: str) -> str:
    return email if email == ANYONE else email.casefold()


# ---------------------------------------------------------------- OWNERS parsing
def parse_owners(text: str, *, source: str = "OWNERS") -> OwnersFile:
    noparent = False
    dir_owners: set[str] = set()
    per_file: list[tuple[str, frozenset[str]]] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        low = line.lower()
        if low == "set noparent":
            noparent = True
        elif low.startswith("per-file"):
            body = line[len("per-file"):].strip()
            if "=" not in body:
                raise ConfigError(f"{source}:{lineno}: per-file needs '=': {raw.strip()!r}")
            globs, owners = body.split("=", 1)
            if "set noparent" in owners.lower():
                # find-owners supports this form; misreading it as an owner named
                # "set noparent" would silently change the owner set.
                raise ConfigError(f"{source}:{lineno}: 'per-file ... = set noparent' is not supported here")
            globs = [g.strip() for g in globs.split(",") if g.strip()]
            names = frozenset(_norm(o.strip()) for o in owners.split(",") if o.strip())
            if not globs or not names:
                raise ConfigError(f"{source}:{lineno}: empty per-file glob or owner list")
            per_file.extend((g, names) for g in globs)
        elif low.startswith(("include", "file:")):
            raise ConfigError(f"{source}:{lineno}: unsupported directive {line.split()[0]!r}")
        elif line == ANYONE or "@" in line:
            dir_owners.add(_norm(line))
        else:
            raise ConfigError(f"{source}:{lineno}: unrecognised line {raw.strip()!r}")
    return OwnersFile(noparent, frozenset(dir_owners), tuple(per_file))


def owners_for_path(path: str, owners_by_dir: dict[str, OwnersFile]) -> frozenset[str]:
    """Accumulate owners from the file's directory upwards, stopping at `set noparent`."""
    p = PurePosixPath(path)
    file_dir = "" if str(p.parent) == "." else str(p.parent)
    owners: set[str] = set()
    for d in [str(x) for x in p.parents]:  # nearest .. '.'
        key = "" if d == "." else d
        of = owners_by_dir.get(key)
        if of is None:
            continue
        # find-owners: `per-file` binds to files in the OWNERS file's own directory,
        # not to subdirectories. Matching it at every ancestor would silently widen
        # ownership relative to Gerrit's native rule.
        if key == file_dir:
            for glob, names in of.per_file:
                if fnmatch.fnmatch(p.name, glob):
                    owners |= set(names)
        owners |= set(of.dir_owners)
        if of.noparent:
            break
    return frozenset(owners)


# ---------------------------------------------------------------- evaluation
def evaluate(
    changed_paths: list[str],
    owners_by_dir: dict[str, OwnersFile],
    author: str,
    *,
    approvals: frozenset[str] = frozenset(),
    cross_owner: str | None = None,
    mode: str = "review",
    exempt_globs: tuple[str, ...] = (),
    exempt_source: str | None = None,
) -> Result:
    author = _norm(author)
    approvals = frozenset(_norm(a) for a in approvals)
    msgs: list[str] = []
    considered = []
    for path in changed_paths:
        # governance files may never exempt themselves: a change that edits OWNERS
        # or the exempt list is judged like any other path (against BASE owners).
        governance = PurePosixPath(path).name == "OWNERS" or path == exempt_source
        if not governance and any(fnmatch.fnmatch(path, g) for g in exempt_globs):
            msgs.append(f"exempt: {path}")
            continue
        considered.append(path)

    violations: list[Violation] = []
    for path in considered:
        owners = owners_for_path(path, owners_by_dir)
        if not owners or ANYONE in owners or author in owners:
            continue
        violations.append(Violation(path, owners))

    if not violations:
        return Result(True, (), tuple(msgs))

    if not cross_owner:
        msgs.append("no `Cross-Owner: <reason>` trailer in the commit message")
        return Result(False, tuple(violations), tuple(msgs))

    if mode == "local":
        msgs.append(
            "local mode: `Cross-Owner` accepted, but an owner of each crossed "
            "path must approve at review time"
        )
        return Result(True, tuple(violations), tuple(msgs))

    # review mode: the trailer is a reason, not permission -- an owner of *each*
    # crossed path must have approved. Otherwise the author unblocks themselves.
    unapproved = [v for v in violations if not (v.owners & approvals)]
    if unapproved:
        msgs.append("`Cross-Owner` given, but no owner of these paths approved the change")
        return Result(False, tuple(unapproved), tuple(msgs))
    msgs.append(f"cross-owner allowed: {cross_owner} (approved by owners)")
    return Result(True, (), tuple(msgs))


# ---------------------------------------------------------------- git layer
def _git(repo: str, *args: str) -> str:
    # quotePath off + explicit utf-8: paths come back raw, not octal-escaped, so a
    # non-ASCII filename cannot dodge the OWNERS lookup by being quoted.
    out = subprocess.run(
        ["git", "-C", repo, "-c", "core.quotePath=false", *args],
        capture_output=True, check=True,
    )
    return out.stdout.decode("utf-8", errors="surrogateescape")


def parse_name_status_z(data: str) -> list[str]:
    """Changed paths from NUL-delimited `git diff --name-status -z -M -C`.

    NUL delimiting means tabs/newlines in filenames cannot break field splits.
    Renames/copies yield both sides (a rename leaves one owner scope and enters
    another). Unknown records fail closed (ConfigError -> exit 2).
    """
    toks = data.split("\0")
    paths: list[str] = []
    i = 0

    def take(n: int, status: str) -> list[str]:
        got = toks[i + 1 : i + 1 + n]
        if len(got) < n or any(t == "" for t in got):
            raise ConfigError(f"truncated diff record at {status!r}")
        return got

    while i < len(toks):
        status = toks[i]
        if status == "":
            i += 1
            continue
        code = status[0]
        if code in "RC":
            paths.extend(take(2, status))
            i += 3
        elif code in "AMDTUXB":
            paths.extend(take(1, status))
            i += 2
        else:
            raise ConfigError(f"unrecognised diff status {status!r}")
    return paths


def changed_paths(repo: str, base_tree: str, rev: str) -> list[str]:
    return parse_name_status_z(
        _git(repo, "diff", "--name-status", "-z", "-M", "-C", base_tree, rev)
    )


def resolve_base_tree(repo: str, rev: str, base: str | None) -> str:
    """The governance snapshot: merge-base of --base and --rev.

    Defaults to the first parent (a root commit falls back to the empty tree).
    Reading OWNERS from here -- never from the change -- is what stops a change
    from granting itself ownership.
    """
    if base is None:
        try:
            return _git(repo, "rev-parse", f"{rev}^").strip()
        except subprocess.CalledProcessError:
            return EMPTY_TREE  # root commit
    return _git(repo, "merge-base", base, rev).strip()


def load_owners_at(repo: str, tree: str) -> dict[str, OwnersFile]:
    if tree == EMPTY_TREE:
        return {}
    listing = _git(repo, "ls-tree", "-r", "--name-only", "-z", tree).split("\0")
    out: dict[str, OwnersFile] = {}
    for rel in listing:
        if rel != "OWNERS" and not rel.endswith("/OWNERS"):
            continue
        text = _git(repo, "show", f"{tree}:{rel}")
        d = str(PurePosixPath(rel).parent)
        out["" if d == "." else d] = parse_owners(text, source=rel)
    return out


def load_exempt_at(repo: str, tree: str, relpath: str | None) -> tuple[str, ...]:
    """Exempt globs come from the BASE tree too -- an author-controlled working-tree
    file would be the same self-grant hole as editing OWNERS in the change."""
    if relpath is None or tree == EMPTY_TREE:
        return ()
    try:
        text = _git(repo, "show", f"{tree}:{relpath}")
    except subprocess.CalledProcessError:
        return ()
    globs = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            globs.append(line)
    return tuple(globs)


def parent_count(repo: str, rev: str) -> int:
    return len(_git(repo, "show", "-s", "--format=%P", rev).split())


# ---------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=".")
    ap.add_argument("--rev", default="HEAD")
    ap.add_argument("--staged", action="store_true",
                    help="check the staged index against HEAD instead of --rev; for "
                         "commit-msg hooks (the commit object does not exist yet). "
                         "OWNERS still comes from HEAD, so staging an OWNERS edit "
                         "grants nothing.")
    ap.add_argument("--message-file", default=None,
                    help="with --staged: the commit message being composed (hook $1), "
                         "read for the Cross-Owner trailer")
    ap.add_argument("--base", default=None,
                    help="target branch/ref; OWNERS and the diff are taken from "
                         "merge-base(base, rev). Default: rev's first parent.")
    ap.add_argument("--author",
                    help="REQUIRED in review mode: the AUTHENTICATED uploader email "
                         "(Gerrit change owner / CI identity). The commit's own "
                         "author field is forgeable and is only used in local mode.")
    ap.add_argument("--approvals", default="", help="comma-separated emails that approved (review mode)")
    ap.add_argument("--mode", choices=("local", "review"), default="local")
    ap.add_argument("--exempt-file", default=None,
                    help="repo-relative file of globs to skip (lockfiles, generated "
                         "code); read from the BASE tree, not the change")
    args = ap.parse_args(argv)

    if args.mode == "review" and not args.author:
        print("owners: --mode review requires --author (the authenticated uploader; "
              "the commit's %ae is forgeable and must not be trusted)", file=sys.stderr)
        return 2
    if args.staged and args.mode == "review":
        print("owners: --staged is a local-hook mode; review mode judges pushed revisions",
              file=sys.stderr)
        return 2

    try:
        if args.staged:
            try:
                base_tree = _git(args.repo, "rev-parse", "HEAD").strip()
            except subprocess.CalledProcessError:
                base_tree = EMPTY_TREE  # unborn branch: first commit
            author = args.author or _git(args.repo, "config", "user.email").strip()
            message = ""
            if args.message_file:
                with open(args.message_file, encoding="utf-8", errors="replace") as fh:
                    message = fh.read()
            changed = parse_name_status_z(
                _git(args.repo, "diff", "--cached", "--name-status", "-z", "-M", "-C", base_tree)
            )
        else:
            base_tree = resolve_base_tree(args.repo, args.rev, args.base)
            author = args.author or _git(args.repo, "show", "-s", "--format=%ae", args.rev).strip()
            message = _git(args.repo, "show", "-s", "--format=%B", args.rev)
            changed = changed_paths(args.repo, base_tree, args.rev)
        owners_by_dir = load_owners_at(args.repo, base_tree)
        exempt = load_exempt_at(args.repo, base_tree, args.exempt_file)
    except ConfigError as exc:
        print(f"owners: {exc}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as exc:
        print(f"owners: git failed: {exc.stderr.decode(errors='replace').strip()}", file=sys.stderr)
        return 2

    if not args.staged and parent_count(args.repo, args.rev) > 1:
        print("owners: note -- merge commit; evaluating its full effect against the base "
              "(a merge does not skip the check)")
    if args.mode == "local" and not args.author:
        print("owners: note -- author taken from the commit (unauthenticated); review "
              "mode will use the authenticated uploader instead")
    if REVERT_RE.search(message):
        print("owners: note -- this looks like a revert; reverting another owner's "
              "change still needs their approval")

    m = CROSS_OWNER_RE.search(message)
    res = evaluate(
        changed,
        owners_by_dir,
        author,
        approvals=frozenset(a.strip() for a in args.approvals.split(",") if a.strip()),
        cross_owner=m.group(1).strip() if m else None,
        mode=args.mode,
        exempt_globs=exempt,
        exempt_source=args.exempt_file,
    )

    for msg in res.messages:
        print(f"owners: {msg}")
    if res.violations:
        label = "out of scope" if not res.ok else "crossed (allowed)"
        print(f"owners: {author} touched paths {label}:")
        for v in res.violations:
            print(f"  {v.path}\n      owners: {', '.join(sorted(v.owners))}")
    if not res.ok:
        print("\nowners: FAIL -- get an owner of each path above to approve, and add "
              "`Cross-Owner: <reason>` to the commit message.", file=sys.stderr)
        return 1
    print("owners: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
