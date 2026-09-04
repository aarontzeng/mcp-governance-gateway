"""`mcpgw-admin` — mint, list, rotate and revoke per-user gateway tokens.

ADR-0007 put minting out of scope and said what a minter must guarantee: an
actor id that was **verified**, and an **atomic write**. ADR-0016 supplies the
first guarantee for deployments with an identity provider. This is the answer
for the ones without: a small reference minter that satisfies both, so the
alternative to an IdP is a command rather than a hand-edited JSON file.

It is deliberately not a portal. What a self-service credential page looks like
is a deployment's own question (`docs/roadmap.md`); what a *store* must contain
for this gateway to read it is not, and that is all this owns.

Three properties it exists to get right, because a hand-edited file gets them
wrong:

- **Tokens come from `secrets.token_urlsafe`.** Not a uuid, not a hash of the
  actor, not something an operator typed.
- **Every write is atomic** — `mkstemp` in the same directory, `fchmod 0600`
  before any bytes, `fsync`, `os.replace`. A half-written token store is a store
  the gateway keeps the last-good version of and an operator does not notice
  (`auth.py` says so out loud on reload failure).
- **`--actor` is never defaulted.** Not from `$USER`, not from the OS. ADR-0007
  wants a verified immutable id; a value this tool invented would be neither,
  and defaulting it is how that requirement quietly becomes a lie.

The token itself is printed **once**, on mint or rotate, and never again: `list`
shows the `token_id` the gateway logs, which is what an operator actually needs
to match a token against an audit line.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Any

_TOKEN_BYTES = 32


def _token_id(token: str) -> str:
    """The same 12 hex characters `auth.Principal.token_id` carries, so an
    operator can match a row here against an audit line without the token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


def _load(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("tokens"), list):
        raise SystemExit(f"{path}: not a token store (expected an object with a 'tokens' list)")
    entries = [e for e in data["tokens"] if isinstance(e, dict)]
    if len(entries) != len(data["tokens"]):
        raise SystemExit(f"{path}: contains an entry that is not an object; refusing to rewrite it")
    return entries


def _save(path: Path, entries: list[dict[str, Any]]) -> None:
    """Atomic, 0600, fsynced — the write ADR-0007 asks a minter for.

    The temp file is created in the SAME directory so `os.replace` is a rename
    within one filesystem; across filesystems it is not atomic. Permissions are
    set before the bytes, not after, so the token is never briefly world-readable.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"tokens": entries}, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        tmp = ""
    finally:
        if tmp:
            os.unlink(tmp)


def _match(entry: dict[str, Any], actor: str, project: str) -> bool:
    return str(entry.get("actor", "")) == actor and str(entry.get("project", "")) == project


def _resolve_store(args) -> Path:
    store = args.store or os.environ.get("GATEWAY_USER_TOKEN_FILE")
    if not store:
        raise SystemExit("no store: pass --store or set GATEWAY_USER_TOKEN_FILE")
    path = Path(store).expanduser()
    # The static store is the operator's file, hand-managed and often under
    # configuration management. Rewriting it from here would silently reformat
    # it and drop any comment structure around it.
    static = os.environ.get("GATEWAY_TOKEN_FILE")
    if static and Path(static).expanduser().resolve(strict=False) == path.resolve(strict=False):
        raise SystemExit(
            "refusing to write GATEWAY_TOKEN_FILE: that store is operator-managed.\n"
            "Mint into GATEWAY_USER_TOKEN_FILE, which the gateway loads as a second source."
        )
    return path


def _print_entry(entry: dict[str, Any]) -> None:
    roles = ",".join(entry.get("roles") or []) or "-"
    print(f"{_token_id(entry['token'])}  {entry.get('actor'):<16} {entry.get('project'):<20} "
          f"{entry.get('issue_project') or '-':<14} {roles}")


def _required_value(name: str, value: str) -> str:
    """Reject what `auth._required_str` would reject, HERE.

    A store this tool writes must be one the gateway can load. `--actor "   "`
    passed argparse's `required=True` happily and then made the whole file
    unloadable on the next reload -- and `auth.py` keeps the last-good set on a
    load failure, so the operator's next revocation would silently not take
    effect either.
    """
    text = (value or "").strip()
    if not text:
        raise SystemExit(f"--{name} must not be blank")
    return text


def cmd_mint(args) -> int:
    args.actor = _required_value("actor", args.actor)
    args.project = _required_value("project", args.project)
    path = _resolve_store(args)
    entries = _load(path)
    if any(_match(e, args.actor, args.project) for e in entries):
        raise SystemExit(
            f"{args.actor} already has a token for {args.project}; use `rotate` to replace it "
            "(which revokes the old one) or `revoke` first."
        )
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    entry: dict[str, Any] = {"token": token, "actor": args.actor, "project": args.project,
                             "roles": sorted(set(args.role or []))}
    if args.issue_project:
        entry["issue_project"] = args.issue_project
    if args.email:
        entry["email"] = args.email
    if args.name:
        entry["name"] = args.name
    entries.append(entry)
    _save(path, entries)
    print(f"minted {_token_id(token)} for {args.actor} on {args.project} in {path}", file=sys.stderr)
    print(token)   # stdout, once, so it can be piped without the prose
    return 0


def cmd_rotate(args) -> int:
    args.actor = _required_value("actor", args.actor)
    args.project = _required_value("project", args.project)
    path = _resolve_store(args)
    entries = _load(path)
    target = next((e for e in entries if _match(e, args.actor, args.project)), None)
    if target is None:
        raise SystemExit(f"no token for {args.actor} on {args.project} in {path}")
    old = _token_id(target["token"])
    target["token"] = secrets.token_urlsafe(_TOKEN_BYTES)
    _save(path, entries)
    print(f"rotated {old} -> {_token_id(target['token'])} ({args.actor} on {args.project}); "
          "the old token stops working as soon as the gateway reloads this file", file=sys.stderr)
    print(target["token"])
    return 0


def cmd_revoke(args) -> int:
    args.actor = _required_value("actor", args.actor)
    args.project = _required_value("project", args.project)
    path = _resolve_store(args)
    entries = _load(path)
    keep = [e for e in entries if not _match(e, args.actor, args.project)]
    if len(keep) == len(entries):
        raise SystemExit(f"no token for {args.actor} on {args.project} in {path}")
    _save(path, keep)
    print(f"revoked {len(entries) - len(keep)} token(s) for {args.actor} on {args.project}", file=sys.stderr)
    return 0


def cmd_list(args) -> int:
    entries = _load(_resolve_store(args))
    rows = [e for e in entries
            if (not args.actor or str(e.get("actor")) == args.actor)
            and (not args.project or str(e.get("project")) == args.project)]
    if not rows:
        print("no tokens", file=sys.stderr)
        return 0
    print(f"{'TOKEN_ID':<13} {'ACTOR':<16} {'PROJECT':<20} {'ISSUE_PROJECT':<14} ROLES", file=sys.stderr)
    for entry in rows:
        _print_entry(entry)
    return 0


def cmd_role(args) -> int:
    args.actor = _required_value("actor", args.actor)
    args.project = _required_value("project", args.project)
    path = _resolve_store(args)
    entries = _load(path)
    target = next((e for e in entries if _match(e, args.actor, args.project)), None)
    if target is None:
        raise SystemExit(f"no token for {args.actor} on {args.project} in {path}")
    roles = set(target.get("roles") or [])
    before = set(roles)
    roles.update(args.role) if args.add else roles.difference_update(args.role)
    target["roles"] = sorted(roles)
    _save(path, entries)
    print(f"{args.actor} on {args.project}: {sorted(before) or '-'} -> {target['roles'] or '-'}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpgw-admin",
        description="Mint and manage per-user tokens for the MCP Governance Gateway. "
                    "Writes GATEWAY_USER_TOKEN_FILE, which the gateway hot-reloads.",
        epilog="With an identity provider you need none of this: see OIDC_ISSUER and ADR-0016.",
    )
    parser.add_argument("--store", help="token store to write (default: $GATEWAY_USER_TOKEN_FILE)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def identity(sub, *, required=True):
        # --actor has no default, ever: ADR-0007 wants a VERIFIED immutable id,
        # and a value this tool guessed from $USER would be neither.
        sub.add_argument("--actor", required=required, help="the caller's immutable id (never defaulted)")
        sub.add_argument("--project", required=required, help="the tenant this token acts in")

    mint = subparsers.add_parser("mint", help="issue a new token (prints it once, on stdout)")
    identity(mint)
    mint.add_argument("--issue-project", help="tenant key for the issue tracker, if different")
    mint.add_argument("--role", action="append", help="repeatable, e.g. --role issue_writer")
    mint.add_argument("--email", help="display label only; also gates credential enrollment")
    mint.add_argument("--name", help="display label shown in memory and docs listings")
    mint.set_defaults(func=cmd_mint)

    rotate = subparsers.add_parser("rotate", help="replace a token in place (prints the new one)")
    identity(rotate)
    rotate.set_defaults(func=cmd_rotate)

    revoke = subparsers.add_parser("revoke", help="remove a token")
    identity(revoke)
    revoke.set_defaults(func=cmd_revoke)

    listing = subparsers.add_parser("list", help="show token ids, never tokens")
    identity(listing, required=False)
    listing.set_defaults(func=cmd_list)

    grant = subparsers.add_parser("grant", help="add a role to an existing token")
    identity(grant)
    grant.add_argument("--role", action="append", required=True)
    grant.set_defaults(func=cmd_role, add=True)

    revoke_role = subparsers.add_parser("revoke-role", help="remove a role from an existing token")
    identity(revoke_role)
    revoke_role.add_argument("--role", action="append", required=True)
    revoke_role.set_defaults(func=cmd_role, add=False)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":   # pragma: no cover
    raise SystemExit(main())
