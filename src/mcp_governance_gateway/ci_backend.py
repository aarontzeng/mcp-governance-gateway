"""Jenkins CI backend: read-only `ci.status` / `ci.builds` / `ci.log` / `ci.artifact`.

Tenancy: Jenkins jobs carry no project concept, so the boundary is a
server-side map `project -> [job names]` (like the docs corpus's repo map).
A token only sees and reads its project's allowlisted jobs; asking for any
other job returns the same "unknown job" error whether it exists or not —
no existence oracle over the Jenkins instance.

Read-only by design: `ci.rerun` (a write) is a separate roadmap item and will
need the confirmation gate; nothing here mutates Jenkins.

Log tails are size-capped: console output can embed anything the build
printed, so we return at most the last N lines of a bounded fetch and never
the whole log.
"""
from __future__ import annotations

import base64
import http.client
import json
import math
from datetime import datetime, timezone
from typing import Any
from urllib import error, parse, request

from .issue_backend import IssueBackendError as CiBackendError  # same shape/semantics
from .memory_backend import RequestContext

_MAX_LOG_FETCH_BYTES = 512_000     # bounded read of consoleText
_MAX_LOG_LINES = 1000
_DEFAULT_LOG_LINES = 200
_MAX_BUILD_COUNT = 50
_DEFAULT_BUILD_COUNT = 10
# One shared budget for the project-wide fan-out: 30 jobs x 50 builds is not an
# answer, it is a denial of the agent's own context window.
_MAX_TOTAL_BUILD_ROWS = 200
STREAM_CHUNK = 64 * 1024           # artifact download stream chunk (see server.py)
_BUILD_ALIASES = ("lastSuccessfulBuild", "lastBuild")  # non-numeric build refs we accept


def _listed_artifact_paths(payload: dict[str, Any]) -> list[str]:
    """The `relativePath` values from an artifact listing, keeping only entries that
    are safe to splice into a URL path.

    The CI server's listing is untrusted input like any other backend response. Two
    things are dropped rather than trusted: an entry that is not a dict with a
    string path (a `null` in the list used to raise AttributeError, which is not a
    CiBackendError and so escaped the error boundary), and a path that is absolute
    or contains a `..` segment. Percent-encoding does not neutralize `..` — dots are
    unreserved, so `quote("..")` is `..` — which means membership in this listing is
    only a traversal guard if the listing itself cannot carry traversal.
    """
    entries = payload.get("artifacts")
    paths = []
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        rel = entry.get("relativePath")
        if not isinstance(rel, str) or not rel:
            continue
        if rel.startswith("/") or ".." in rel.split("/"):
            continue
        paths.append(rel)
    return paths


def _build_ms(value: object) -> int | None:
    """A Jenkins millisecond field, or None when it is not a usable number.

    Copying the field through untyped let a `"timestamp": []` in the CI server's
    reply become a list in an MCP result; the listing is untrusted input like any
    other backend response.

    The `isfinite` check is not theoretical: `json.loads` accepts the non-standard
    `NaN` and `Infinity` literals by default, and `int(nan)` raises a ValueError
    that is not a CiBackendError -- so a CI server emitting one would have escaped
    the error boundary as a 500 rather than a clean tool error.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return int(value)


def _normalize_build_row(entry: object) -> dict[str, Any] | None:
    """One build, as this gateway reports builds — or None if the entry is unusable.

    Shared by `ci.status` and `ci.builds` so the two cannot drift: they had already
    started to, with the listing rejecting a non-string `result` and the last-build
    row passing one through.

    `startedAt` is the field to reason with. Jenkins speaks epoch milliseconds and
    every other timestamp this gateway emits is ISO-8601 (`audit.utc_now_iso`,
    memory `createdAt`, issue `updatedAt`), which matters most in a tool whose
    whole payload is time. The raw `timestamp` stays beside it because `ci.status`
    has emitted it since 0.1.0 and removing it would break a caller for tidiness.
    """
    if not isinstance(entry, dict):
        return None
    number = entry.get("number")
    # bool is an int in Python, so a JSON `true` would otherwise surface as build #1.
    if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
        return None
    building = bool(entry.get("building"))
    result = entry.get("result")
    started_ms = _build_ms(entry.get("timestamp"))
    return {
        "build": number,
        "result": ("BUILDING" if building else (result if isinstance(result, str) and result else "UNKNOWN")),
        "building": building,
        "timestamp": started_ms,
        "startedAt": _iso_from_ms(started_ms),
        "durationMs": _build_ms(entry.get("duration")),
    }


def _iso_from_ms(millis: int | None) -> str | None:
    if millis is None:
        return None
    try:
        return datetime.fromtimestamp(millis / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None  # a nonsense epoch from the CI server is not a reason to fail the read


def _listed_builds(payload: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    """The build rows from a job's build listing, newest first.

    Two bounds, doing two different jobs. The `{0,N}` suffix in the query is what
    keeps the *fetch* small on a Jenkins that understands it. This slice bounds
    the *answer* -- it is what holds the output contract when a server returns
    more rows than were asked for. It is NOT a defence against an unbounded
    listing: `_fetch` reads at most 512KB, so a listing larger than that is cut
    mid-JSON and surfaces as "CI returned invalid JSON" before this runs. That
    is fail-closed, and it is the honest description of the bound.
    """
    entries = payload.get("builds")
    rows: list[dict[str, Any]] = []
    for entry in entries if isinstance(entries, list) else []:
        row = _normalize_build_row(entry)
        if row is None:
            continue
        rows.append(row)
        if len(rows) >= limit:
            break
    return rows


# The never-built row carries the SAME keys as a real one, with nulls. A caller
# that has to branch on which keys are present is a caller we made work for.
_NEVER_BUILT = {"build": None, "result": "UNKNOWN", "building": False,
                "timestamp": None, "startedAt": None, "durationMs": None}


def _safe_build_ref(build: object) -> str:
    """A build ref safe to splice into a Jenkins URL path: a positive int or a known
    alias. Anything else is rejected — this value lands in a path segment, so it must
    never be able to carry one."""
    if build is None:
        return "lastSuccessfulBuild"
    if isinstance(build, int) and not isinstance(build, bool):
        if build <= 0:
            raise CiBackendError("invalid build number", status=400)
        return str(build)
    text = str(build).strip()
    if text in _BUILD_ALIASES:
        return text
    if text.isdigit() and int(text) > 0:
        return text
    raise CiBackendError("invalid build reference", status=400)


def load_ci_jobs(path: str) -> dict[str, list[str]]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("ci jobs file must be a JSON object of project -> [job, ...]")
    jobs: dict[str, list[str]] = {}
    for project, names in data.items():
        if not isinstance(names, list) or not all(isinstance(n, str) and n.strip() for n in names):
            raise ValueError(f"ci jobs for {project!r} must be a list of job names")
        jobs[str(project)] = [n.strip() for n in names]
    return jobs


class JenkinsHttpBackend:
    def __init__(
        self,
        base_url: str,
        user: str | None,
        token: str | None,
        jobs_by_project: dict[str, list[str]],
        timeout_sec: float = 10,
        artifact_base_url: str | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth = None
        if user and token:
            self._auth = "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode()
        self._jobs = jobs_by_project
        self._timeout_sec = timeout_sec
        # Public base for the download endpoint ci.artifact hands back. Unset leaves a
        # relative reference the caller prepends its own origin to.
        self._artifact_base = (artifact_base_url or "").rstrip("/")

    def has_project(self, project: str | None) -> bool:
        return bool(project) and bool(self._jobs.get(project))

    # --- tools ---------------------------------------------------------

    def status(self, context: RequestContext) -> dict[str, Any]:
        """Last-build status for every allowlisted job of the caller's project."""
        jobs = self._project_jobs(context)
        out = []
        for name in jobs:
            out.append(self._job_status(name))
        return {"jobs": out, "count": len(out)}

    def log(self, job: str, context: RequestContext, lines: int | None = None) -> dict[str, Any]:
        """Tail of the last build's console for one allowlisted job."""
        jobs = self._project_jobs(context)
        name = (job or "").strip()
        if name not in jobs:
            # Allowlist first: a job outside the project's list is "unknown"
            # whether or not it exists on the Jenkins instance.
            raise CiBackendError("unknown job for this project", status=404)
        n = max(1, min(int(lines or _DEFAULT_LOG_LINES), _MAX_LOG_LINES))
        raw = self._request_text(f"/job/{parse.quote(name, safe='')}/lastBuild/consoleText")
        tail = raw.splitlines()[-n:]
        meta = self._job_status(name)
        return {
            "job": name,
            "build": meta.get("build"),
            "result": meta.get("result"),
            "lines": tail,
            "truncated": len(raw) >= _MAX_LOG_FETCH_BYTES,
        }

    def builds(self, job: str | None, context: RequestContext, count: int | None = None) -> dict[str, Any]:
        """Recent build history, newest first, for one job or for the whole project.

        `ci.status` answers "is it green now". This answers "is this flaky" and
        "when did it start failing", within the window it returns -- a job red for
        longer than `count` builds looks the same as one red since the beginning,
        which is a real limit of a last-N view and is stated in the tool text.

        `job` is optional for the same reason `ci.status` takes no job at all: the
        question that motivates this tool ("which of my jobs regressed") is
        project-shaped, and requiring a job name would make an agent answer it
        with one call per job, each costing its own quota tick and audit event.
        Omitted, it walks the project's allowlist and shares one row budget so a
        project with many jobs still cannot produce an unbounded result.
        """
        per_job = max(1, min(int(_DEFAULT_BUILD_COUNT if count is None else count), _MAX_BUILD_COUNT))
        if job is None or not str(job).strip():
            names = list(self._project_jobs(context))
            per_job = max(1, min(per_job, _MAX_TOTAL_BUILD_ROWS // len(names)))
        else:
            names = [self._require_allowlisted(job, context)]
        return {"jobs": [self._job_builds(name, per_job) for name in names], "count": len(names)}

    def _job_builds(self, name: str, limit: int) -> dict[str, Any]:
        try:
            data = self._request_json(
                f"/job/{parse.quote(name, safe='')}/api/json"
                f"?tree=builds[number,result,building,timestamp,duration]{{0,{limit}}}"
            )
        except CiBackendError as exc:
            if exc.status == 404:
                # Allowlisted but absent from Jenkins (renamed, deleted). One such
                # job must not fail the whole project's answer -- the same call
                # `status()` already makes for the same reason. The cost is that a
                # deleted job and one that has never run are the same answer here,
                # exactly as they are both UNKNOWN to `ci.status`.
                return {"job": name, "builds": [], "count": 0}
            raise
        rows = _listed_builds(data, limit)
        return {"job": name, "builds": rows, "count": len(rows)}

    def artifacts(self, job: str, context: RequestContext, build: object = None) -> dict[str, Any]:
        """One build's artifacts, metadata only, each with a gateway download URL.

        Never returns bytes: a build artifact is routinely tens of megabytes, which has
        no business in an MCP JSON result or in the agent's context. The file itself
        comes from the /ci/artifact streaming endpoint."""
        name = self._require_allowlisted(job, context)
        ref = _safe_build_ref(build)
        data = self._request_json(
            f"/job/{parse.quote(name, safe='')}/{ref}/api/json?tree=number,artifacts[fileName,relativePath]"
        )
        number = data.get("number")
        items = [
            {
                "fileName": rel.rsplit("/", 1)[-1],
                "relativePath": rel,
                "download": self._download_url(name, number, rel),
            }
            for rel in _listed_artifact_paths(data)
        ]
        return {"job": name, "build": number, "artifacts": items, "count": len(items)}

    def open_artifact(self, job: str, build: object, rel_path: str, context: RequestContext):
        """Open a streaming handle to one artifact, after enforcing the tenant
        allowlist AND that `rel_path` is a real artifact of that build.

        That second check is the anti-traversal guard: only paths Jenkins itself lists
        are fetchable, so `..`, an absolute path or any other invented one cannot be
        spliced through. Returns the open response; the caller streams and closes it."""
        return self.open_located(self.locate_artifact(job, build, rel_path, context))

    def locate_artifact(self, job: str, build: object, rel_path: str, context: RequestContext) -> str:
        """The validation half of open_artifact: returns the upstream path of an
        artifact the caller may fetch, or raises. Split out so a caller can tell a
        refusal (job or path unknown: audit nothing the caller typed) from an open
        that failed AFTER validation (audit the artifact it failed for)."""
        name = self._require_allowlisted(job, context)
        ref = _safe_build_ref(build)
        rel = (rel_path or "").strip()
        listing = self._request_json(
            f"/job/{parse.quote(name, safe='')}/{ref}/api/json?tree=artifacts[relativePath]"
        )
        if rel not in set(_listed_artifact_paths(listing)):
            # Identical to a foreign job: never reveal whether the path exists.
            raise CiBackendError("unknown artifact for this build", status=404)
        segments = "/".join(parse.quote(part, safe="") for part in rel.split("/"))
        return f"/job/{parse.quote(name, safe='')}/{ref}/artifact/{segments}"

    def open_located(self, upstream_path: str):
        """The network half of open_artifact; takes what locate_artifact returned."""
        return self._open(upstream_path)

    # --- internals -----------------------------------------------------

    def _require_allowlisted(self, job: str, context: RequestContext) -> str:
        jobs = self._project_jobs(context)
        name = (job or "").strip()
        if name not in jobs:
            raise CiBackendError("unknown job for this project", status=404)
        return name

    def _download_url(self, job: str, build: object, rel_path: str) -> str:
        query = parse.urlencode({"job": job, "build": build if build is not None else "", "path": rel_path})
        return f"{self._artifact_base}/ci/artifact?{query}"

    def _open(self, path: str):
        """Open (but do not read) a Jenkins response, for streaming."""
        req = request.Request(self._base_url + path, headers=self._headers(), method="GET")
        try:
            return request.urlopen(req, timeout=self._timeout_sec)
        except error.HTTPError as exc:
            raise CiBackendError(f"CI HTTP {exc.code}", status=exc.code) from exc
        except (OSError, http.client.HTTPException, ValueError) as exc:
            # A garbled status line or an over-long header is an HTTPException, not
            # an OSError, and a credential or redirect the request cannot be encoded
            # with is a ValueError; either way the CI is unusable, not the caller.
            raise CiBackendError("CI unavailable") from exc

    def _project_jobs(self, context: RequestContext) -> list[str]:
        names = self._jobs.get(context.project or "")
        if not names:
            raise CiBackendError("no CI jobs are configured for this project", status=404)
        return names

    def _job_status(self, name: str) -> dict[str, Any]:
        try:
            data = self._request_json(
                f"/job/{parse.quote(name, safe='')}/lastBuild/api/json"
                "?tree=number,result,building,timestamp,duration,url"
            )
        except CiBackendError as exc:
            if exc.status == 404:  # job exists in config but has no builds / was renamed
                return {"job": name, **_NEVER_BUILT}
            raise
        row = _normalize_build_row(data)
        if row is None:  # a reply with no usable build number reads as "never built"
            return {"job": name, **_NEVER_BUILT}
        return {"job": name, **row}

    def _request_json(self, path: str) -> dict[str, Any]:
        raw = self._fetch(path)
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CiBackendError("CI returned invalid JSON") from exc
        return decoded if isinstance(decoded, dict) else {}

    def _request_text(self, path: str) -> str:
        return self._fetch(path).decode("utf-8", errors="replace")

    def _fetch(self, path: str) -> bytes:
        req = request.Request(self._base_url + path, headers=self._headers(), method="GET")
        try:
            with request.urlopen(req, timeout=self._timeout_sec) as response:
                return response.read(_MAX_LOG_FETCH_BYTES)
        except error.HTTPError as exc:
            raise CiBackendError(f"CI HTTP {exc.code}", status=exc.code) from exc
        except (OSError, http.client.HTTPException, ValueError) as exc:
            # A garbled status line or an over-long header is an HTTPException, not
            # an OSError, and a credential or redirect the request cannot be encoded
            # with is a ValueError; either way the CI is unusable, not the caller.
            raise CiBackendError("CI unavailable") from exc

    def _headers(self) -> dict[str, str]:
        # identity: an artifact is streamed as the bytes the build wrote, and the
        # download route refuses a body Jenkins (or a proxy) coded anyway.
        h = {"Accept": "application/json", "Accept-Encoding": "identity"}
        if self._auth:
            h["Authorization"] = self._auth
        return h
