"""Propose a document change for review, without being able to publish it.

This is the seam the docs write path hangs on, and the shape of it is the whole
governance property. There are four operations: open a change, revise it,
comment on it, read it back. There is no `merge`, no `approve`, no
`delete_branch`, no `push` to a protected ref, and no way to add one without
editing this file.

Be exact about what that buys, because "an agent may propose, only a person may
publish" needs THREE things and this file is only the first:

1. **The gateway cannot publish.** No method, so no configuration mistake and no
   policy inversion can make it. That is this file's job and it is done here.
2. **The credential must not be able to publish.** The enrolled token is the
   caller's own, and if it carries more than "open a pull request" then the
   *power* to merge exists even though this code never uses it. Scope is the
   deployment's to get right; `docs/adapters/docs.md` names the smallest token
   that works.
3. **The repository must not let the author merge unreviewed.** If it does, the
   "person who publishes" is the same GitHub identity that proposed, and the
   separation is a second browser tab rather than a second principal.

An agent talking only to this gateway cannot publish under any of those
conditions — the credential never leaves the process, so the agent has the
gateway's tools and not the token. What (2) and (3) protect against is the
*human's own* token being used elsewhere, and a repository configured so that
proposing and publishing are the same act. Neither is something this file can
enforce, and saying "enforced by the absence of a method" full stop was
overclaiming.

Two consequences of going through a review host's REST API rather than pushing
from the corpus clone, both worth having on purpose:

- **The clone stays read-only.** A write never touches the server's working
  tree, so it cannot race the refresher that keeps the read path fresh.
- **No credential reaches a command line.** The caller's own token is a header,
  not an argument to `git`, so it cannot land in a process listing.

Every call is made under the CALLER's own credential. The host's own access
control is therefore the authorization, and the proposal carries the person's
name rather than a service account's — which is what makes "an agent may
propose" a statement about a human being accountable for the proposal.
"""
from __future__ import annotations

import base64
import http.client
import json
import re
import secrets
from dataclasses import dataclass
from typing import Any, Protocol
from urllib import error, parse, request

from .issue_backend import (
    IssueBackendError as ReviewBackendError,  # same shape/semantics
    _MAX_RESPONSE_BYTES,
)
from .memory_backend import RequestContext

# The attribution footer, in the shape `issue_backend` already stamps on notes.
# Its presence is what tells a human reader that a comment came through the
# gateway rather than from the person directly, so it is not decoration.
FOOTER = "[via mcp-governance-gateway | actor={actor} | audit={request_id}]"

_GITHUB_REPO_RE = re.compile(r"\A[A-Za-z0-9._-]+/[A-Za-z0-9._-]+\Z")
# A GitLab project may be a numeric id or a namespaced path several levels deep.
_GITLAB_PROJECT_RE = re.compile(r"\A[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\Z")
_BRANCH_RE = re.compile(r"\A[A-Za-z0-9._/-]+\Z")
_SUPPORTED = {"github", "gitlab"}


@dataclass(frozen=True)
class ReviewSpec:
    """Where one project's proposals go, resolved from the docs repo map.

    Separate from the corpus `_Spec` on purpose: a project may have a corpus and
    no review host, which is exactly how a corpus stays read-only. It is never
    the other way round — there is nothing to propose a change to without a
    corpus to read.
    """

    project: str
    type: str
    repo: str
    api: str
    base_branch: str

    @property
    def backend_key(self) -> str:
        """The credential-store backend this project's proposals authenticate as.

        Distinct from the `issues` credential for the same host type: a person's
        issue-tracker token and their docs-host token are different secrets with
        different scopes, and the store is keyed by (actor, backend) precisely so
        both can exist.
        """
        return f"docs-{self.type}"


def parse_review_spec(project: str, entry: dict[str, Any], branch: str) -> ReviewSpec | None:
    """The `review` block of a docs-repos entry, or None when there is none.

    Absent means this project's corpus is read-only, which is the default and
    needs no configuration. Present but malformed is an error at load time
    rather than a surprise at the first write: an operator who wrote a `review`
    block believes writes are on.
    """
    raw = entry.get("review")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError(f"docs repo entry for {project!r}: 'review' must be an object")

    kind = str(raw.get("type", "")).strip().lower()
    if kind not in _SUPPORTED:
        raise ValueError(
            f"docs repo entry for {project!r}: review type {kind or '(missing)'!r} "
            f"is not one of {', '.join(sorted(_SUPPORTED))}"
        )
    repo = str(raw.get("repo", "")).strip()
    pattern = _GITHUB_REPO_RE if kind == "github" else _GITLAB_PROJECT_RE
    if not pattern.fullmatch(repo):
        raise ValueError(
            f"docs repo entry for {project!r}: review repo {repo!r} is not a valid {kind} project"
        )
    api = str(raw.get("api", "")).strip().rstrip("/")
    if not api:
        api = "https://api.github.com" if kind == "github" else "https://gitlab.com/api/v4"
    if not api.startswith(("http://", "https://")):
        raise ValueError(f"docs repo entry for {project!r}: review api {api!r} must be an http(s) URL")

    # The branch proposals target defaults to the branch the corpus is read from,
    # so the two cannot drift into proposing against something nobody reads.
    base = str(raw.get("baseBranch", "") or branch).strip()
    if not _BRANCH_RE.fullmatch(base):
        raise ValueError(f"docs repo entry for {project!r}: review baseBranch {base!r} is not a branch name")
    return ReviewSpec(project=project, type=kind, repo=repo, api=api, base_branch=base)


class ReviewBackend(Protocol):
    """What a review host must do for the docs write path — and no more.

    Implementations take the caller's credential as an argument rather than
    holding one: there is no service account here, by construction.
    """

    def open_change(self, spec: ReviewSpec, path: str, content: str, message: str,
                    credential: str, context: RequestContext) -> dict[str, Any]:
        """Create a branch, put one file on it, and open a proposal. Returns
        `{number, url, branch}`. Must refuse rather than overwrite when `path`
        already exists on the base branch."""

    def update_change(self, spec: ReviewSpec, path: str, content: str, message: str,
                      base_sha: str, credential: str, context: RequestContext) -> dict[str, Any]:
        """Revise an existing document as a proposal. `base_sha` is the blob the
        caller read; a document that moved under them is a 409, never a silent
        overwrite."""

    def comment(self, spec: ReviewSpec, change_ref: int, body: str,
                credential: str, context: RequestContext) -> dict[str, Any]:
        """Add a plain comment. It must NOT be an approval, a review, or anything
        that can satisfy a required-approvals rule."""

    def get_change(self, spec: ReviewSpec, change_ref: int,
                   credential: str, context: RequestContext) -> dict[str, Any]:
        """Read one proposal back: state, title, url, and whether it is merged."""


def stamped(body: str, context: RequestContext) -> str:
    """A comment body with the gateway footer appended.

    Never optional: an unstamped comment is indistinguishable from one the person
    wrote themselves, and the difference is the point.
    """
    return f"{body.rstrip()}\n\n{FOOTER.format(actor=context.actor, request_id=context.request_id)}"


def _validate_change_ref(change_ref: Any) -> int:
    """Validate that change_ref is a positive integer before using in URL segments."""
    if isinstance(change_ref, bool) or not isinstance(change_ref, int) or change_ref <= 0:
        raise ReviewBackendError(
            f"change_ref must be a positive integer, got {change_ref!r}",
            status=400,
        )
    return change_ref


def _quote_path(path: str) -> str:
    """Validate path and percent-encode each segment safely."""
    if not isinstance(path, str) or not path or path.startswith("/"):
        raise ReviewBackendError(f"invalid document path: {path!r}", status=400)
    segments = path.split("/")
    if any(seg == ".." for seg in segments):
        raise ReviewBackendError(f"path must not contain '..' segments: {path!r}", status=400)
    return "/".join(parse.quote(seg, safe="") for seg in segments)


def _derive_branch(path: str) -> str:
    """Derive a proposal branch name matching [a-z0-9._/-]+ with a random suffix."""
    suffix = secrets.token_hex(4)
    slug = re.sub(r"[^a-z0-9._-]+", "-", path.lower()).strip("-")
    slug = slug[:85].rstrip("-")
    if not slug:
        slug = "doc"
    return f"mcpgw/{slug}-{suffix}"


class GitHubReviewBackend:
    """Propose document changes via GitHub REST API.

    Implements the ReviewBackend protocol. Holds no service account or
    credential; every call authenticates with the caller's own token.
    """

    def __init__(self, timeout_sec: float = 30.0) -> None:
        self._timeout_sec = timeout_sec

    def _request(
        self,
        spec: ReviewSpec,
        method: str,
        path: str,
        credential: str,
        body: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{spec.api.rstrip('/')}{path}"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {credential}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = request.Request(url, data=data, headers=headers, method=method)
        try:
            with request.urlopen(req, timeout=self._timeout_sec) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except error.HTTPError as exc:
            raise ReviewBackendError(f"review host HTTP {exc.code}", status=exc.code) from exc
        except (OSError, http.client.HTTPException, ValueError) as exc:
            # A garbled or truncated reply is an HTTPException, not an OSError, and
            # a credential or redirect the request cannot be encoded with is a
            # ValueError; either way the backend is unusable, not the caller.
            raise ReviewBackendError("review host unavailable") from exc
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise ReviewBackendError("review host response too large")
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ReviewBackendError("review host returned invalid JSON") from exc

    def _propose(
        self,
        spec: ReviewSpec,
        path: str,
        content: str,
        message: str,
        base_sha: str | None,
        credential: str,
        context: RequestContext,
    ) -> dict[str, Any]:
        quoted_path = _quote_path(path)

        # Step 1: GET /repos/{repo}/git/ref/heads/{base} -> .object.sha
        try:
            ref_data = self._request(
                spec,
                "GET",
                f"/repos/{spec.repo}/git/ref/heads/{spec.base_branch}",
                credential,
            )
        except ReviewBackendError as exc:
            if exc.status == 404:
                raise ReviewBackendError(
                    f"corpus repository {spec.repo!r} has no commits yet on branch {spec.base_branch!r}",
                    status=404,
                ) from exc
            raise

        base_head_sha = ref_data.get("object", {}).get("sha") if isinstance(ref_data, dict) else None
        if not base_head_sha:
            raise ReviewBackendError("review host returned ref without object.sha")

        # Step 2: POST /repos/{repo}/git/refs with {"ref": "refs/heads/<branch>", "sha": <base sha>}
        branch = _derive_branch(path)
        self._request(
            spec,
            "POST",
            f"/repos/{spec.repo}/git/refs",
            credential,
            body={"ref": f"refs/heads/{branch}", "sha": base_head_sha},
        )

        # Step 3: PUT /repos/{repo}/contents/{path}
        b64_content = base64.b64encode(content.encode("utf-8")).decode("ascii")
        put_body: dict[str, Any] = {
            "message": message,
            "branch": branch,
            "content": b64_content,
        }
        if base_sha is not None:
            put_body["sha"] = base_sha

        try:
            self._request(
                spec,
                "PUT",
                f"/repos/{spec.repo}/contents/{quoted_path}",
                credential,
                body=put_body,
            )
        except ReviewBackendError as exc:
            if base_sha is None and exc.status == 422:
                raise ReviewBackendError(
                    f"document already exists: {path!r}",
                    status=409,
                ) from exc
            if base_sha is not None and exc.status == 409:
                raise ReviewBackendError(
                    f"document changed since it was read: {path!r}",
                    status=409,
                ) from exc
            raise

        # Step 4: POST /repos/{repo}/pulls with {"title", "head", "base", "body"} -> .number, .html_url
        lines = message.strip().splitlines()
        title = lines[0].strip() if lines else path
        pr_body = "\n".join(lines[1:]).strip() if len(lines) > 1 else ""

        pr_data = self._request(
            spec,
            "POST",
            f"/repos/{spec.repo}/pulls",
            credential,
            body={
                "title": title,
                "head": branch,
                "base": spec.base_branch,
                "body": pr_body,
            },
        )
        if not isinstance(pr_data, dict) or "number" not in pr_data or "html_url" not in pr_data:
            raise ReviewBackendError("review host returned invalid pull request response")
        return {
            "number": pr_data["number"],
            "url": pr_data["html_url"],
            "branch": branch,
        }

    def open_change(
        self,
        spec: ReviewSpec,
        path: str,
        content: str,
        message: str,
        credential: str,
        context: RequestContext,
    ) -> dict[str, Any]:
        return self._propose(spec, path, content, message, None, credential, context)

    def update_change(
        self,
        spec: ReviewSpec,
        path: str,
        content: str,
        message: str,
        base_sha: str,
        credential: str,
        context: RequestContext,
    ) -> dict[str, Any]:
        if not isinstance(base_sha, str) or not base_sha.strip():
            raise ReviewBackendError("base_sha is required for update_change", status=400)
        return self._propose(spec, path, content, message, base_sha.strip(), credential, context)

    def comment(
        self,
        spec: ReviewSpec,
        change_ref: int,
        body: str,
        credential: str,
        context: RequestContext,
    ) -> dict[str, Any]:
        _validate_change_ref(change_ref)
        res = self._request(
            spec,
            "POST",
            f"/repos/{spec.repo}/issues/{change_ref}/comments",
            credential,
            body={"body": body},
        )
        return res if isinstance(res, dict) else {}

    def get_change(
        self,
        spec: ReviewSpec,
        change_ref: int,
        credential: str,
        context: RequestContext,
    ) -> dict[str, Any]:
        _validate_change_ref(change_ref)
        data = self._request(
            spec,
            "GET",
            f"/repos/{spec.repo}/pulls/{change_ref}",
            credential,
        )
        if not isinstance(data, dict):
            raise ReviewBackendError("review host returned invalid pull request response")
        head = data.get("head") or {}
        branch = head.get("ref", "") if isinstance(head, dict) else ""
        return {
            "number": data.get("number", change_ref),
            "state": data.get("state", ""),
            "title": data.get("title", ""),
            "url": data.get("html_url", ""),
            "merged": bool(data.get("merged", False)),
            "branch": branch,
        }

