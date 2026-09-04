"""Propose a document change for review, without being able to publish it.

This is the seam the docs write path hangs on, and the shape of it is the whole
governance property. There are four operations: open a change, revise it,
comment on it, read it back. There is no `merge`, no `approve`, no
`delete_branch`, no `push` to a protected ref, and no way to add one without
editing this file — an agent can propose and advise, and only a person can
publish. That is enforced by the absence of a method rather than by a policy
check somebody could misconfigure.

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

import re
from dataclasses import dataclass
from typing import Any, Protocol

from .issue_backend import IssueBackendError as ReviewBackendError  # same shape/semantics
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
