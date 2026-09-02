"""Read-only docs corpus: per-project git repos served as `docs.search` / `docs.get`.

One docs repo per gateway project (tenancy = repo = the token's `project` claim).
The corpus is a server-side clone refreshed on a throttled pull loop; only
markdown under `raw/` and `wiki/` is indexed. The clone keeps full history
because per-file author provenance needs the first commit that touched a path —
see `_refresh`. Search is a small stdlib
BM25 (ASCII words + CJK unigrams/bigrams) — deliberately not a vector index:
agentmemory already owns semantic search, and this corpus is reviewed prose.

Existence-oracle rule: `get` answers **purely from the in-memory index** — a
path that exists in the repo but is not served (README, dotfiles, non-markdown)
takes the same code path and produces the same error as a path that never
existed, so `docs.get` cannot be used to probe the repo tree.
"""
from __future__ import annotations

import json
import math
import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from .memory_backend import ActorLabels, RequestContext, _display_actor

_WORD_RE = re.compile(r"[a-z0-9_]+")
_PROJECT_KEY_RE = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]*")  # no leading dot: not ".", "..", ".git"
_CJK_RE = re.compile("[\\u3400-\\u9fff]")
_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.S)
_HEADING_RE = re.compile(r"^#\s+(.+)$", re.M)


class DocsBackendError(Exception):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def tokenize(text: str) -> list[str]:
    """ASCII words plus CJK unigrams and bigrams (BM25 needs tokens; CJK has no spaces)."""
    low = text.lower()
    tokens = _WORD_RE.findall(low)
    cjk = _CJK_RE.findall(low)
    tokens.extend(cjk)
    tokens.extend(a + b for a, b in zip(cjk, cjk[1:]))
    return tokens


def parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Minimal frontmatter: top-level `key: value` lines. Values are strings,
    except a flow-style list (`tags: [a, b, c]`) which parses to a list --
    returning it raw would hand consumers the literal string "[a, b, c]"."""
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}, text
    meta: dict[str, Any] = {}
    for line in m.group(1).splitlines():
        if ":" in line and not line.startswith((" ", "\t", "-")):
            k, v = line.split(":", 1)
            if not k.strip():
                continue
            v = v.strip().strip("'\"")
            if v.startswith("[") and v.endswith("]"):
                meta[k.strip()] = [t.strip().strip("'\"") for t in v[1:-1].split(",") if t.strip()]
            else:
                meta[k.strip()] = v
    return meta, text[m.end():]


@dataclass
class _Doc:
    path: str
    title: str
    text: str        # body without frontmatter
    meta: dict[str, Any]
    created_by: str | None = None
    updated_by: str | None = None
    tokens: dict[str, int] = field(default_factory=dict)
    length: int = 0


class _Bm25Index:
    K1 = 1.5
    B = 0.75

    def __init__(self, docs: list[_Doc]) -> None:
        self._docs = docs
        self._df: dict[str, int] = {}
        total = 0
        for d in docs:
            toks = tokenize(d.title + "\n" + d.text)
            d.length = len(toks)
            total += d.length
            counts: dict[str, int] = {}
            for t in toks:
                counts[t] = counts.get(t, 0) + 1
            d.tokens = counts
            for t in counts:
                self._df[t] = self._df.get(t, 0) + 1
        self._avg_len = (total / len(docs)) if docs else 0.0

    def search(self, query: str, limit: int) -> list[tuple[float, _Doc]]:
        q = tokenize(query)
        if not q or not self._docs:
            return []
        n = len(self._docs)
        scored: list[tuple[float, _Doc]] = []
        for d in self._docs:
            score = 0.0
            for t in q:
                tf = d.tokens.get(t)
                if not tf:
                    continue
                df = self._df.get(t, 0)
                idf = math.log(1 + (n - df + 0.5) / (df + 0.5))
                denom = tf + self.K1 * (1 - self.B + self.B * d.length / (self._avg_len or 1))
                score += idf * tf * (self.K1 + 1) / denom
            if score > 0:
                scored.append((score, d))
        scored.sort(key=lambda s: (-s[0], s[1].path))
        return scored[:limit]


@dataclass(frozen=True)
class _Spec:
    """One project's resolved corpus specification, captured once per request.

    `generation` identifies the registry publication it came from, so a request
    cannot read the url from one reload and the branch from the next.
    `fingerprint` is what a snapshot is keyed to: deliberately (url, branch) and
    NOT the generation, because an unrelated project's edit bumps the generation
    and must not invalidate this project's corpus.
    """
    project: str
    url: str
    branch: str
    generation: int

    @property
    def fingerprint(self) -> tuple[str, str]:
        return (self.url, self.branch)


@dataclass(frozen=True)
class _Registry:
    """An immutable (generation, mapping) pair, published as one object.

    Rebinding a dict left two pieces of dependent state -- the map and its file
    signature -- with no version relation between them, so a reader could act on a
    map while a snapshot keyed to the previous one still looked fresh."""
    generation: int
    repos: dict[str, dict[str, Any]]
    signature: tuple


@dataclass
class _Snapshot:
    head: str
    docs: dict[str, _Doc]
    index: _Bm25Index
    refreshed_at: float
    spec: tuple[str, str]   # the _Spec.fingerprint this snapshot was built from


class DocsCorpus:
    """Per-project corpora. `repos` maps project -> {"url": ..., "branch": ...}."""

    SERVED_DIRS = ("raw/", "wiki/")
    # Corpus caps, checked from the tree listing before any content is read. A
    # docs repository is reviewed prose, so these are far above any real corpus
    # and still small enough that one runaway repository cannot exhaust the
    # gateway's memory on refresh. Exceeding one fails the refresh (503).
    MAX_DOCS = 5000
    MAX_DOC_BYTES = 2 * 1024 * 1024
    MAX_CORPUS_BYTES = 64 * 1024 * 1024

    def __init__(
        self,
        repos: dict[str, dict[str, str]],
        clone_dir: str,
        *,
        pull_interval_sec: float = 300.0,
        git_timeout_sec: float = 30.0,
        repos_file: str | None = None,
        actor_labels: "ActorLabels | None" = None,
    ) -> None:
        self._clone_dir = clone_dir
        self._pull_interval = pull_interval_sec
        self._git_timeout = git_timeout_sec
        self._snapshots: dict[str, _Snapshot] = {}
        # Three narrow locks rather than one wide one. The old single lock was held
        # across clone/fetch/reset, so every project's docs calls queued behind one
        # project's remote Git I/O; widening it further would have made that worse.
        self._registry_lock = threading.Lock()   # publishing a new registry
        self._snap_lock = threading.Lock()       # the snapshot dict, never held over I/O
        self._refresh_locks: dict[str, threading.Lock] = {}  # one per project
        # Maps an opaque git-author name (an employee id, where a deployment
        # re-keyed identities to one) to a readable label, the same mechanism the
        # memory listings use. Git history cannot be rewritten, so the mapping
        # happens on the way out.
        self._actor_labels = actor_labels
        # When set, a project added or edited in this file takes effect without a
        # restart -- same mtime/size/inode signature as the token store's hot
        # reload, for the same reasons: st_mtime alone can miss two same-second
        # writes on a coarse-mtime filesystem, and an atomic write swaps in a new
        # inode every time.
        self._repos_file = repos_file
        self._registry = _Registry(generation=0, repos=dict(repos), signature=self._repos_file_sig())

    def _repos_file_sig(self) -> tuple:
        if not self._repos_file:
            return ()
        try:
            st = os.stat(self._repos_file)
            return (st.st_mtime_ns, st.st_size, st.st_ino)
        except OSError:
            return (None, None, None)

    def _current_registry(self) -> _Registry:
        """The registry, reloading first when the file changed.

        Publication is one assignment of one immutable object, so a reader either
        sees the whole old registry or the whole new one -- generation included.
        The lock is held only for the file read, never over any Git work."""
        if not self._repos_file:
            return self._registry
        signature = self._repos_file_sig()
        if signature == self._registry.signature:
            return self._registry
        with self._registry_lock:
            if signature == self._registry.signature:  # another thread published it
                return self._registry
            try:
                repos = load_docs_repos(self._repos_file)
            except Exception as exc:
                # Keep the last-good map on a missing/partial/corrupt write, so a bad
                # save can never take every project's docs tools down. The signature
                # advances regardless, so a failed parse is not retried on every call.
                print(f"docs repos file reload failed; keeping the last-good map: {exc}", file=sys.stderr, flush=True)
                self._registry = _Registry(self._registry.generation, self._registry.repos, signature)
                return self._registry
            self._registry = _Registry(self._registry.generation + 1, repos, signature)
            return self._registry

    def _resolve_spec(self, project: str | None) -> _Spec:
        """Capture this project's specification once, from one registry publication."""
        registry = self._current_registry()
        entry = registry.repos.get(project or "")
        if not entry:
            raise DocsBackendError("no docs corpus is configured for this project", status=404)
        return _Spec(
            project=project or "",
            url=str(entry["url"]),
            branch=str(entry.get("branch", "master")),
            generation=registry.generation,
        )

    def _refresh_lock_for(self, project: str) -> threading.Lock:
        with self._snap_lock:
            lock = self._refresh_locks.get(project)
            if lock is None:
                lock = self._refresh_locks[project] = threading.Lock()
            return lock

    def has_project(self, project: str | None) -> bool:
        return bool(project) and project in self._current_registry().repos

    # ---------------------------------------------------------------- tools
    def search(self, query: str, limit: int, context: RequestContext) -> dict[str, Any]:
        snap = self._snapshot_for(context)
        hits = snap.index.search(query, limit)
        results = []
        for score, doc in hits:
            results.append(
                {
                    "path": doc.path,
                    "title": doc.title,
                    "snippet": _snippet(doc.text, query),
                    "updated": doc.meta.get("updated") or doc.meta.get("date"),
                    "commit": snap.head,
                    "score": round(score, 3),
                }
            )
        return {"results": results, "commit": snap.head, "count": len(results)}

    def list(self, context: RequestContext) -> dict[str, Any]:
        """All served documents (path/title/updated) — the corpus is small by design.

        `status`, `staleAfter` and `decisionStatus` ride along when a document
        declares them: they are already parsed into the snapshot, and a reader who
        can see "deprecated" or "stale on 2026-10-31" in the listing can skip a
        document instead of fetching it. Absent means nothing is claimed. Staleness
        stays a raw date here, so each consumer compares it against its own today.
        """
        snap = self._snapshot_for(context)
        items = []
        for d in sorted(snap.docs.values(), key=lambda d: d.path):
            item: dict[str, Any] = {
                "path": d.path,
                "title": d.title,
                "updated": d.meta.get("updated") or d.meta.get("date"),
            }
            if d.meta.get("status"):
                item["status"] = d.meta["status"]
            if d.meta.get("stale_after"):
                item["staleAfter"] = d.meta["stale_after"]
            if d.meta.get("decision_status"):
                item["decisionStatus"] = d.meta["decision_status"]
            items.append(item)
        return {"documents": items, "commit": snap.head, "count": len(items)}

    def get(self, path: str, context: RequestContext) -> dict[str, Any]:
        snap = self._snapshot_for(context)
        # Answer purely from the index: unserved-but-present and never-existed paths
        # share this exact code path (no filesystem access here).
        doc = snap.docs.get(_normalize(path))
        if doc is None:
            raise DocsBackendError("document not found", status=404)
        result = {
            "path": doc.path,
            "title": doc.title,
            "frontmatter": doc.meta,
            "text": doc.text,
            "commit": snap.head,
        }
        # Same display treatment as the memory listings: an opaque author key maps
        # through the token store and an email's domain is stripped, so docs and
        # memory name the same person the same way. A real-name author from a direct
        # push passes through untouched.
        labels = self._actor_labels.get() if self._actor_labels else {}
        if doc.created_by:
            result["createdBy"] = _display_actor(doc.created_by, labels)
        if doc.updated_by:
            result["updatedBy"] = _display_actor(doc.updated_by, labels)
        return result

    # ---------------------------------------------------------------- corpus
    def _snapshot_for(self, context: RequestContext) -> _Snapshot:
        spec = self._resolve_spec(context.project)
        cached = self._eligible_snapshot(spec)
        if cached is not None:
            return cached
        # Per project, so one project's remote Git work does not block another's.
        with self._refresh_lock_for(spec.project):
            cached = self._eligible_snapshot(spec)   # another thread may have just done it
            if cached is not None:
                return cached
            try:
                snap = self._refresh(spec)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                stale = self._snapshots.get(spec.project)
                if stale is not None and stale.spec == spec.fingerprint:
                    # A pull hiccup against the SAME repository: serving the last good
                    # snapshot is a freshness compromise the reader can live with --
                    # said on the operator's log, since the reader cannot tell, and
                    # a repository that keeps failing should not stay quiet.
                    print(
                        f"docs corpus refresh failed for project {spec.project!r}; "
                        "serving the last good snapshot until the next pull interval",
                        file=sys.stderr, flush=True,
                    )
                    stale.refreshed_at = time.monotonic()
                    return stale
                # A different specification, though, means the old snapshot is another
                # corpus. Unavailable is the honest answer; quietly serving the
                # previous repository's documents would not be.
                # git's stderr names the remote (and can quote a URL, a host, or a
                # sideband message from the server), so it goes to the operator's
                # log, never into the tool error the client reads.
                stderr = exc.stderr if isinstance(exc.stderr, bytes) else b""
                timed_out = isinstance(exc, subprocess.TimeoutExpired)
                print(
                    f"docs corpus refresh failed for project {spec.project!r}: "
                    + ("git timed out" if timed_out else stderr.decode(errors="replace").strip()[:500]),
                    file=sys.stderr, flush=True,
                )
                detail = "git timed out" if timed_out else "git clone/fetch failed"
                raise DocsBackendError(f"docs corpus unavailable: {detail}", status=503) from exc
            # Resolved before taking the snapshot lock, so no lock is ever held while
            # another is acquired.
            still_current = self._resolve_spec_quietly(spec.project) == spec.fingerprint
            with self._snap_lock:
                # Only publish if the specification is still the one we fetched. If it
                # changed underneath us, this snapshot is already history.
                if still_current:
                    self._snapshots[spec.project] = snap
            return snap

    def _eligible_snapshot(self, spec: _Spec) -> _Snapshot | None:
        """A cached snapshot is eligible only if it was built from the CURRENT
        specification and is still fresh. Age alone was the bug: a retargeted
        project kept serving the old repository until the pull interval expired."""
        with self._snap_lock:
            snap = self._snapshots.get(spec.project)
        if snap is None or snap.spec != spec.fingerprint:
            return None
        return snap if (time.monotonic() - snap.refreshed_at) < self._pull_interval else None

    def _resolve_spec_quietly(self, project: str) -> tuple[str, str] | None:
        entry = self._current_registry().repos.get(project)
        if not entry:
            return None
        return (str(entry["url"]), str(entry.get("branch", "master")))

    def _refresh(self, spec: _Spec) -> _Snapshot:
        # The specification arrives as a value. Reading it from the mutable map here
        # was a race: a concurrent reload that dropped the project raised KeyError
        # past the error boundary, and one that changed it produced a snapshot built
        # from two different specifications.
        project, url, branch = spec.project, spec.url, spec.branch
        dest = os.path.join(self._clone_dir, project)
        if not os.path.isdir(os.path.join(dest, ".git")):
            os.makedirs(self._clone_dir, exist_ok=True)
            # Full history, not --depth 1. Per-file provenance needs the first commit
            # that touched a path, and in a shallow clone the tip is grafted as a root
            # commit -- `log --name-only` then reports every file as introduced there,
            # by whoever happened to push last. That is not a missing answer but a
            # confidently wrong one. The corpus is reviewed prose and small by design,
            # so the history it costs is small too.
            self._git(None, "clone", "--branch", branch, url, dest)
        else:
            # The repos file is hot-reloaded, so a project's URL can change under an
            # existing clone; without this it would keep polling the old repository.
            self._git(dest, "remote", "set-url", "origin", url)
            if self._git(dest, "rev-parse", "--is-shallow-repository").strip() == "true":
                # Upgrade a clone left by an earlier shallow-clone release in place,
                # so deploying this does not require deleting the cache directory.
                self._git(dest, "fetch", "--unshallow", "origin", branch)
            else:
                self._git(dest, "fetch", "origin", branch)
            self._git(dest, "reset", "--hard", "FETCH_HEAD")
        head = self._git(dest, "rev-parse", "HEAD").strip()
        docs = self._load_docs(dest)
        return _Snapshot(
            head=head, docs=docs, index=_Bm25Index(list(docs.values())),
            refreshed_at=time.monotonic(), spec=spec.fingerprint,
        )

    def _load_docs(self, dest: str) -> dict[str, _Doc]:
        # Read the tree, not the working directory. `ls-tree` carries each entry's
        # mode, so symlinks (120000) and submodules (160000) are dropped before
        # anything is opened: `open()` on a checked-out symlink follows it, and a
        # docs commit could point `wiki/x.md` at any file on the gateway host.
        # Content then comes from the object store by blob id, so no path under
        # the clone is ever opened by name.
        listing = self._git(dest, "ls-tree", "-r", "-l", "-z", "HEAD").split("\0")
        wanted: list[tuple[str, str, int]] = []
        total = 0
        for entry in listing:
            info, _, rel = entry.partition("\t")
            fields = info.split()
            if len(fields) != 4 or not rel:
                continue
            mode, kind, oid, size = fields
            if kind != "blob" or mode not in ("100644", "100755"):
                continue
            if not rel.endswith(".md") or not rel.startswith(self.SERVED_DIRS):
                continue
            if any(part.startswith(".") for part in PurePosixPath(rel).parts):
                continue
            nbytes = int(size)
            if nbytes > self.MAX_DOC_BYTES:
                raise DocsBackendError(
                    f"docs corpus exceeds limits: {rel} is {nbytes} bytes", status=503)
            total += nbytes
            wanted.append((rel, oid, nbytes))
        if len(wanted) > self.MAX_DOCS:
            raise DocsBackendError(
                f"docs corpus exceeds limits: {len(wanted)} documents", status=503)
        if total > self.MAX_CORPUS_BYTES:
            raise DocsBackendError(
                f"docs corpus exceeds limits: {total} bytes of markdown", status=503)
        blobs = self._read_blobs(dest, wanted)
        authors = self._file_authors(dest)
        docs: dict[str, _Doc] = {}
        for rel, oid, _nbytes in wanted:
            raw = blobs[oid].decode("utf-8", errors="replace")
            meta, body = parse_frontmatter(raw)
            # The frontmatter parser is general, so `title: [a, b]` legitimately
            # parses to a list; this consumer needs a string and says so, rather
            # than letting a list reach the index and raise a TypeError there.
            declared = meta.get("title")
            title = (
                declared.strip() if isinstance(declared, str) and declared.strip()
                else (_first_heading(body) or PurePosixPath(rel).stem)
            )
            created_by, updated_by = authors.get(rel, (None, None))
            docs[rel] = _Doc(
                path=rel, title=title, text=body.strip(), meta=meta,
                created_by=created_by, updated_by=updated_by,
            )
        return docs

    def _read_blobs(self, dest: str, wanted: list[tuple[str, str, int]]) -> dict[str, bytes]:
        """Blob contents by object id, in one `cat-file --batch` round trip.

        The batch output is `<oid> blob <size>\n<content>\n` per request, framed by
        the size in bytes, so it is parsed as bytes and decoded per document."""
        if not wanted:
            return {}
        request = "".join(f"{oid}\n" for _rel, oid, _size in wanted).encode("ascii")
        out = self._git(dest, "cat-file", "--batch", input=request, raw=True)
        blobs: dict[str, bytes] = {}
        pos = 0
        for rel, oid, _size in wanted:
            end = out.find(b"\n", pos)
            header = out[pos:end].decode("ascii", errors="replace").split() if end >= 0 else []
            if len(header) != 3 or header[0] != oid or header[1] != "blob":
                raise DocsBackendError(f"docs corpus unreadable: {rel}", status=503)
            nbytes = int(header[2])
            blobs[oid] = out[end + 1:end + 1 + nbytes]
            pos = end + 1 + nbytes + 1
        return blobs

    def _file_authors(self, dest: str) -> dict[str, tuple[str, str]]:
        """Current-path creator/updater names, from the complete Git log.

        The log is newest-first, so a path's first occurrence is its latest
        updater and its last occurrence is its creator. NUL-delimited paths keep
        unusual but valid filenames from corrupting neighbouring entries.
        """
        history = self._git(
            dest, "log", "-z", "--format=%x1e%aN", "--name-only", "--", *self.SERVED_DIRS,
        )
        created: dict[str, str] = {}
        updated: dict[str, str] = {}
        for commit in history.split("\x1e"):
            if not commit:
                continue
            author, separator, paths = commit.partition("\0")
            author = author.strip("\r\n")
            if not separator or not author:
                continue
            for path in paths.split("\0"):
                # Git puts one line break between the pretty header and the first
                # NUL-delimited path; later paths carry no prefix.
                rel = path[1:] if path.startswith("\n") else path
                if not rel.startswith(self.SERVED_DIRS) or not rel.endswith(".md"):
                    continue
                updated.setdefault(rel, author)
                created[rel] = author
        return {path: (creator, updated[path]) for path, creator in created.items() if path in updated}

    def _git(self, cwd: str | None, *args: str, input: bytes | None = None, raw: bool = False):
        out = subprocess.run(
            ["git", "-c", "core.quotePath=false", *args],
            cwd=cwd, capture_output=True, check=True, timeout=self._git_timeout, input=input,
        )
        if raw:
            return out.stdout
        return out.stdout.decode("utf-8", errors="surrogateescape")


def load_docs_repos(path: str) -> dict[str, dict[str, str]]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("docs repos file must be a JSON object of project -> {url, branch}")
    repos: dict[str, dict[str, str]] = {}
    for project, spec in data.items():
        # The key names the clone directory under the cache root, so it must be a
        # single path component: a key like "../other" would make the gateway fetch
        # into -- and hard-reset -- a checkout outside the cache, and ".git" is the
        # marker every clone is probed for.
        if not _PROJECT_KEY_RE.fullmatch(str(project)):
            raise ValueError(f"docs repo key {project!r} must be a plain name (letters, digits, . _ -; no leading dot)")
        if not isinstance(spec, dict) or not spec.get("url"):
            raise ValueError(f"docs repo entry for {project!r} needs a url")
        repos[str(project)] = {"url": str(spec["url"]), "branch": str(spec.get("branch", "master"))}
    return repos


def _normalize(path: str) -> str:
    return str(PurePosixPath(path.strip().lstrip("/")))


def _first_heading(body: str) -> str | None:
    m = _HEADING_RE.search(body)
    return m.group(1).strip() if m else None


def _snippet(text: str, query: str, radius: int = 90) -> str:
    low = text.lower()
    pos = -1
    for tok in tokenize(query):
        pos = low.find(tok)
        if pos >= 0:
            break
    if pos < 0:
        pos = 0
    start = max(0, pos - radius)
    end = min(len(text), pos + radius)
    frag = " ".join(text[start:end].split())
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return prefix + frag + suffix
