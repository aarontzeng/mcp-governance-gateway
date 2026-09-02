"""GitLab issue backend: the second `IssueBackend` (ADR-0012 made room for it).

Same normalized shapes and the same tenancy discipline as the Redmine backend:
every operation is scoped to the caller's `issue_project` (a GitLab project id
or URL-encoded `group/name` path), searches are forced to it, and get/note/
status address issues through the project-scoped endpoint so an issue from
another project is a 404 by construction — plus a defense-in-depth re-check of
`project_id` on every item we return.

Deliberate v1 boundaries (documented, not accidental):
  * Per-user PATs via the generalized credential store: authorship writes route
    through the caller's own PAT when a key_resolver is wired (same Decision-5
    semantics and enforced mode as Redmine), including the existence check
    that gates a write; the shared token covers plain reads and the
    optional-mode fallback.
  * GitLab issues have two states (`opened`/`closed`); workflow lives in
    labels. `update_status` therefore accepts only OPEN/CLOSED (+aliases), and
    `done_ratio` is rejected rather than silently dropped.
  * Issues are addressed by their project-scoped `iid` — the number people see
    in the GitLab UI — not the instance-global `id`.
"""
from __future__ import annotations

import json
from typing import Any, Callable
from urllib import error, parse, request

from .issue_backend import (
    IssueBackend,
    IssueBackendError,
    _MAX_RESPONSE_BYTES,
    _d,
    _enrollment_hint,
    _normalize_status,
    _with_attribution,
    _attribution,
)
from .memory_backend import RequestContext
from .redmine_keystore import KeyState

# Fields with no GitLab equivalent wired here. Refused by name on every write path:
# silently dropping a field the caller asked to set is worse than refusing it, and a
# refusal that only some paths perform is the same bug with a smaller blast radius.
_REDMINE_ONLY_FIELDS = ("dueDate", "priority", "parentIssue", "category")


def _reject_redmine_only(fields: dict[str, Any], where: str) -> None:
    present = sorted(f for f in _REDMINE_ONLY_FIELDS if fields.get(f) is not None)
    if present:
        raise ValueError(
            f"GitLab issues do not support {', '.join(present)} via {where} "
            "(dueDate/priority/parentIssue/category are Redmine-only in this gateway)"
        )


def _assignee_field(value: Any) -> tuple[str, str]:
    """(param name, value) -- GitLab takes a numeric id or a username, distinguished
    by whether the caller-supplied string is all-digits."""
    text = str(value).strip()
    return ("assignee_id", text) if text.isdigit() else ("assignee_username", text)


_CLOSE_NAMES = {"CLOSED", "CLOSE"}
_REOPEN_NAMES = {"OPEN", "OPENED", "REOPEN", "REOPENED", "NEW", "IN_PROGRESS"}


class GitLabHttpBackend(IssueBackend):
    def __init__(
        self,
        base_url: str,
        token: str | None,
        timeout_sec: float = 10,
        key_resolver: Callable[[str], tuple[KeyState, str | None]] | None = None,
        enforce_personal: bool = False,
        credential_portal_url: str | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token  # shared token: non-authorship reads + optional fallback
        self._timeout_sec = timeout_sec
        self._portal_url = (credential_portal_url or "").rstrip("/") or None
        # Per-user attribution: when a resolver is wired, authorship writes route
        # through the caller's own PAT (same Decision-5 semantics as Redmine).
        self._key_resolver = key_resolver
        self._enforce_personal = enforce_personal
        # issue_project claim -> (numeric project id, display name)
        self._project_cache: dict[str, tuple[int, str]] = {}

    def _write_key(self, context: RequestContext) -> tuple[str | None, bool]:
        """(token, is_personal) for an authorship write, or fail loud (Decision 5/B)."""
        if self._key_resolver is None:
            if self._enforce_personal:
                raise IssueBackendError("enforced personal-token mode requires a key store", status=428)
            return self._token, False
        state, personal = self._key_resolver(context.actor)
        if state is KeyState.OK and personal:
            return personal, True
        if state is KeyState.DEGRADED and self._enforce_personal:
            # Same promise as the Redmine backend: enforced mode said writes carry the
            # caller's own token, and a degraded store cannot deliver that. Telling
            # the caller to enroll would send them to fix a server-side condition.
            raise IssueBackendError(
                "the credential store is temporarily unusable and this gateway enforces personal-token "
                "writes; re-enrolling is not the fix and would be refused -- operators can see it "
                "on /healthz",
                status=503,
            )
        if state is KeyState.UNDECRYPTABLE:
            raise IssueBackendError(
                "your personal GitLab token could not be decrypted (the keystore may have been rotated); "
                "please re-enroll it via the gateway's credential-enrollment endpoint"
                + _enrollment_hint(self._portal_url),
                status=409,
            )
        if self._enforce_personal:
            raise IssueBackendError(
                "this operation needs your personal GitLab token; enroll it via the gateway's "
                "credential-enrollment endpoint and try again" + _enrollment_hint(self._portal_url),
                status=428,
            )
        return self._token, False

    # --- public operations -------------------------------------------------

    def get(self, issue_id: str, context: RequestContext) -> dict[str, Any]:
        pid, pname = self._resolve_project(context)
        issue = self._get_issue_in_project(issue_id, pid)
        # Same rule as the Redmine backend: description on the single-issue read
        # only, never on the list shapes search/mine/create share.
        result = self._normalize(issue, pid, pname)
        result["description"] = issue.get("description")
        return result

    def search(self, filters: dict[str, Any], limit: int, context: RequestContext) -> dict[str, Any]:
        pid, pname = self._resolve_project(context)
        params: dict[str, Any] = {"per_page": max(1, min(limit, 100))}
        status = filters.get("status")
        if status is not None:
            params["state"] = _state_filter(status)
        assignee = filters.get("assignee")
        if assignee is not None:
            key, value = _assignee_field(assignee)
            params[key] = value
        data = self._request("GET", f"/projects/{pid}/issues", params=params)
        items = data if isinstance(data, list) else []
        scoped: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            if item.get("project_id") != pid:  # defense-in-depth re-filter
                continue
            scoped.append(self._normalize(item, pid, pname))
            if len(scoped) >= limit:
                break
        return {"issues": scoped, "count": len(scoped)}

    def create(self, fields: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        _reject_redmine_only(fields, "create")
        token, personal = self._write_key(context)  # fail-loud early
        pid, pname = self._resolve_project(context)
        body = {
            "title": fields["subject"],
            "description": _with_attribution(fields.get("description"), context, personal=personal),
        }
        if fields.get("assignee") is not None:
            key, value = _assignee_field(fields["assignee"])
            body[key] = value
        issue = self._request("POST", f"/projects/{pid}/issues", body=body, token=token)
        if not isinstance(issue, dict) or issue.get("iid") is None:
            raise IssueBackendError("issue tracker returned an unexpected create response")
        if issue.get("project_id") != pid:
            raise IssueBackendError("created issue is not in the expected project")
        result = self._normalize(issue, pid, pname)
        result["created"] = True
        return result

    def add_note(self, issue_id: str, note: str, context: RequestContext) -> dict[str, Any]:
        token, personal = self._write_key(context)  # fail-loud early
        pid, _ = self._resolve_project(context)
        # Verify under the same token the write will use: the shared token
        # must not vouch for an issue the personal PAT cannot read.
        self._get_issue_in_project(issue_id, pid, token=token)
        self._request(
            "POST", f"/projects/{pid}/issues/{_iid(issue_id)}/notes",
            body={"body": _with_attribution(note, context, personal=personal)}, token=token,
        )
        return {"noted": True, "id": str(issue_id)}

    def update_status(
        self, issue_id: str, status: str, done_ratio: int | None, context: RequestContext,
        *, assignee: str | None = None, planning: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized = _normalize_status(status)
        if normalized in _CLOSE_NAMES:
            event, result_status = "close", "CLOSED"
        elif normalized in _REOPEN_NAMES:
            event, result_status = "reopen", "OPEN"
        else:
            raise ValueError(
                f"unknown status '{status}' for GitLab; allowed: OPEN, CLOSED "
                "(GitLab workflow beyond open/closed lives in labels)"
            )
        if done_ratio is not None:
            raise ValueError("GitLab issues have no done ratio; omit doneRatio")
        # Same posture as done_ratio above, and the same refusal create() performs.
        _reject_redmine_only(planning or {}, "update_status")
        token, personal = self._write_key(context)  # fail-loud early
        pid, _ = self._resolve_project(context)
        self._get_issue_in_project(issue_id, pid, token=token)
        body: dict[str, Any] = {"state_event": event}
        if assignee is not None:
            key, value = _assignee_field(assignee)
            body[key] = value
        self._request("PUT", f"/projects/{pid}/issues/{_iid(issue_id)}", body=body, token=token)
        # Record who asked, like the Redmine path does via the journal note.
        self._request(
            "POST", f"/projects/{pid}/issues/{_iid(issue_id)}/notes",
            body={"body": _attribution(context, personal=personal)}, token=token,
        )
        return {"updated": True, "id": str(issue_id), "status": result_status}

    def verify_key(self, plaintext: str) -> dict[str, Any]:
        """Confirm a submitted PAT and return its owner (shape matches Redmine's:
        id / login / mail) so the portal's email-binding works unchanged."""
        user = self._request("GET", "/user", token=plaintext)
        if not isinstance(user, dict) or user.get("id") is None:
            raise IssueBackendError("could not verify gitlab token", status=401)
        return {"id": user.get("id"), "login": user.get("username"), "mail": user.get("email")}

    def categories(self, context: RequestContext) -> dict[str, Any]:
        # A Redmine concept (a per-project single-valued enum). GitLab's nearest
        # equivalent is labels, which are freeform and multi-valued -- different
        # enough in shape that mapping one onto the other here would be a guess
        # presented as a fact.
        raise IssueBackendError(
            "this project's issue tracker is GitLab, which has no category concept — GitLab uses labels instead",
            status=400,
        )

    def mine(self, limit: int, context: RequestContext) -> dict[str, Any]:
        """Same fail-loud-always semantics as the Redmine backend: scope=assigned_to_me
        on the shared token resolves to the shared token's own issues, not the
        caller's, so this never falls back to it."""
        hint = _enrollment_hint(self._portal_url)
        if self._key_resolver is None:
            raise IssueBackendError(
                "issues.mine needs your personal GitLab token, and this gateway has no key store "
                "configured" + hint,
                status=428,
            )
        state, personal = self._key_resolver(context.actor)
        if state is KeyState.DEGRADED:
            raise IssueBackendError(
                "the credential store is temporarily unusable, so the gateway cannot tell which issues "
                "are yours; answering from the shared token would return its issues as if they were "
                "yours. Re-enrolling is not the fix and would be refused -- operators can see it "
                "on /healthz",
                status=503,
            )
        if state is KeyState.UNDECRYPTABLE:
            raise IssueBackendError(
                "your personal GitLab token could not be decrypted (the keystore may have been rotated); "
                "please re-enroll it via the gateway's credential-enrollment endpoint" + hint,
                status=409,
            )
        if state is not KeyState.OK or not personal:
            raise IssueBackendError(
                "issues.mine needs your personal GitLab token to tell which issues are yours — the shared "
                "token cannot stand in for you; enroll it via the gateway's credential-enrollment endpoint "
                "and try again" + hint,
                status=428,
            )
        return self.list_assigned_to_me(personal, context, limit)

    def list_assigned_to_me(self, personal_key: str, context: RequestContext, limit: int = 25) -> dict[str, Any]:
        """Issues in the caller's project assigned to them, on their own PAT."""
        pid, pname = self._resolve_project(context)
        params = {"scope": "assigned_to_me", "per_page": max(1, min(limit, 100))}
        data = self._request("GET", f"/projects/{pid}/issues", params=params, token=personal_key)
        items = data if isinstance(data, list) else []
        scoped = [self._normalize(i, pid, pname) for i in items
                  if isinstance(i, dict) and i.get("project_id") == pid][:limit]
        return {"issues": scoped, "count": len(scoped)}

    # --- internals ---------------------------------------------------------

    def _resolve_project(self, context: RequestContext) -> tuple[int, str]:
        key = context.issue_project
        if not key:
            raise IssueBackendError("token has no issue project")
        if key in self._project_cache:
            return self._project_cache[key]
        data = self._request("GET", f"/projects/{parse.quote(str(key), safe='')}")
        pid = data.get("id") if isinstance(data, dict) else None
        if not isinstance(pid, int):
            raise IssueBackendError("could not resolve gitlab project")
        name = data.get("name") if isinstance(data.get("name"), str) else str(key)
        self._project_cache[key] = (pid, name)
        return pid, name

    def _get_issue_in_project(
        self, issue_id: str, pid: int, *, token: str | None = None
    ) -> dict[str, Any]:
        # The endpoint itself is project-scoped, so a foreign iid 404s naturally;
        # the explicit re-check guards against a confused/hostile backend.
        try:
            issue = self._request("GET", f"/projects/{pid}/issues/{_iid(issue_id)}", token=token)
        except IssueBackendError as exc:
            if exc.status == 404:
                raise IssueBackendError("issue not found", status=404) from exc
            raise
        if not isinstance(issue, dict) or issue.get("project_id") != pid:
            raise IssueBackendError("issue not found", status=404)
        return issue

    def _normalize(self, issue: dict[str, Any], pid: int, pname: str) -> dict[str, Any]:
        assigned = _d(issue.get("assignee"))
        if not assigned:
            assignees = issue.get("assignees")
            if isinstance(assignees, list) and assignees and isinstance(assignees[0], dict):
                assigned = assignees[0]
        assignee = None
        if assigned.get("id") is not None:
            assignee = {"id": str(assigned.get("id")), "displayName": assigned.get("name")}
        state = "OPEN" if issue.get("state") == "opened" else _normalize_status(issue.get("state"))
        return {
            "id": str(issue.get("iid", "")),
            "projectId": str(pid),
            "projectName": pname,
            "subject": issue.get("title"),
            "status": state,
            "tracker": _normalize_status(issue.get("issue_type")),
            "category": None,  # GitLab has no category concept (see categories())
            "assignee": assignee,
            "doneRatio": None,
            "updatedAt": issue.get("updated_at"),
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        token: str | None = None,
    ) -> Any:
        url = f"{self._base_url}/api/v4{path}"
        if params:
            url = f"{url}?{parse.urlencode(params)}"
        headers = {"Accept": "application/json"}
        # Explicit token routes authorship writes / me-reads through the caller's
        # own PAT; the default uses the shared token for everything non-authorship.
        key = token if token is not None else self._token
        if key:
            headers["PRIVATE-TOKEN"] = key
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = request.Request(url, data=data, headers=headers, method=method)
        try:
            with request.urlopen(req, timeout=self._timeout_sec) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except error.HTTPError as exc:
            raise IssueBackendError(f"issue tracker HTTP {exc.code}", status=exc.code) from exc
        except OSError as exc:
            raise IssueBackendError("issue tracker unavailable") from exc
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise IssueBackendError("issue tracker response too large")
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise IssueBackendError("issue tracker returned invalid JSON") from exc


def _iid(value: Any) -> str:
    text = str(value).strip().lstrip("#")
    if not text.isdigit():
        raise ValueError("invalid issue reference (GitLab issues are addressed by numeric iid)")
    return text


def _state_filter(status: Any) -> str:
    if isinstance(status, str):
        low = status.strip().lower()
        if low in ("open", "opened"):
            return "opened"
        if low in ("close", "closed"):
            return "closed"
        if low == "*":
            return "all"
    raise ValueError(f"unknown status filter '{status}' for GitLab; allowed: open, closed, *")
