from __future__ import annotations

import http.client
import json
import re
import time
from datetime import date
from typing import Any, Callable
from urllib import error, parse, request

from .memory_backend import RequestContext
from .redmine_keystore import KeyState


class IssueBackendError(Exception):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


# Status filter values Redmine takes verbatim, so they never need an id lookup.
_STATUS_FILTER_PASSTHROUGH = frozenset({"open", "closed", "*"})

# Instance-global name -> id vocabularies the write path needs, as (path, response
# key). All three are per-instance and none may be hardcoded: a fresh Redmine seeds
# statuses New..Rejected 1..6, trackers Bug/Feature/Support 1..3 and the priority
# enumeration somewhere after the document categories, and any instance that added,
# renamed or reordered its own diverges from all of that. Read from the instance and
# an added or renamed value works with no configuration; guessed, a wrong id does
# not fail — it writes the issue somewhere the caller did not ask for.
# How long a resolved vocabulary may be trusted. A cache hit does not re-validate,
# so between an admin renaming a status and this expiring, the old name still
# resolves to the old id -- and that id now means something else, which writes the
# issue into a state nobody asked for. Bounded staleness is the trade: the
# alternative is a request per write for a table that changes a few times a year.
_ENUM_CACHE_TTL_SEC = 300.0

_ENUM_SOURCES: dict[str, tuple[str, str]] = {
    "status": ("/issue_statuses.json", "issue_statuses"),
    "tracker": ("/trackers.json", "trackers"),
    "priority": ("/enumerations/issue_priorities.json", "issue_priorities"),
}


_DUE_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

_MAX_RESPONSE_BYTES = 2_000_000


def _due_date(value: Any) -> str:
    text = str(value)
    if not _DUE_DATE_RE.match(text):
        raise ValueError(f"dueDate must be YYYY-MM-DD, got '{text}'")
    try:
        date.fromisoformat(text)  # rejects 2026-02-31 and friends, which the regex accepts
    except ValueError as exc:
        raise ValueError(f"dueDate is not a real date: '{text}'") from exc
    return text


def _d(value: Any) -> dict[str, Any]:
    # Treat a non-dict (malformed / hostile backend) nested field as empty.
    return value if isinstance(value, dict) else {}


def _normalize_status(name: Any) -> str:
    if not isinstance(name, str):
        return ""
    return name.strip().upper().replace(" ", "_")


def _enrollment_hint(portal_url: str | None) -> str:
    """Where-to-go suffix for the errors that ask a caller to enroll a credential.

    Empty when the deployment has not configured a portal: the gateway must not
    hardcode a host, and a message pointing at nothing is worse than one that
    just says what is wrong."""
    return f" -> {portal_url}" if portal_url else ""


def _attribution(context: RequestContext, *, personal: bool = False) -> str:
    # With a personal key the Redmine author is already the real user, so the stamp
    # is trimmed to just the audit id — kept (not dropped) so the write is still
    # marked as agent/gateway-mediated and correlates to the audit log. With the
    # shared service key the author is the service account, so the actor is named too.
    if personal:
        return f"[via mcp-governance-gateway | audit={context.request_id}]"
    return f"[via mcp-governance-gateway | actor={context.actor} | audit={context.request_id}]"


def _with_attribution(text: str | None, context: RequestContext, *, personal: bool = False) -> str:
    body = (text or "").strip()
    footer = _attribution(context, personal=personal)
    return f"{body}\n\n{footer}" if body else footer


class IssueBackend:
    def get(self, issue_id: str, context: RequestContext) -> dict[str, Any]:
        raise NotImplementedError

    def search(self, filters: dict[str, Any], limit: int, context: RequestContext) -> dict[str, Any]:
        raise NotImplementedError

    def create(self, fields: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        raise NotImplementedError

    def add_note(self, issue_id: str, note: str, context: RequestContext) -> dict[str, Any]:
        raise NotImplementedError

    def update_status(
        self, issue_id: str, status: str, done_ratio: int | None, context: RequestContext,
        *, assignee: str | None = None, planning: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        raise NotImplementedError

    def mine(self, limit: int, context: RequestContext) -> dict[str, Any]:
        raise NotImplementedError

    def categories(self, context: RequestContext) -> dict[str, Any]:
        raise NotImplementedError


class RedmineHttpBackend(IssueBackend):
    """Adapter over the Redmine REST API.

    Every operation is scoped to the caller's `issue_project` (resolved to a
    numeric project id). The client never supplies a project: searches are forced
    to that project, and get/note/status verify the target issue belongs to it
    before reading or mutating, so an issue id from another project cannot be
    reached. Responses are normalized to a stable shape; raw backend bodies and
    errors are never propagated.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        timeout_sec: float = 10,
        key_resolver: Callable[[str], tuple[KeyState, str | None]] | None = None,
        enforce_personal: bool = False,
        credential_portal_url: str | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key  # shared/service key: non-authorship reads + fallback
        self._timeout_sec = timeout_sec
        self._project_id_cache: dict[str, int] = {}
        self._portal_url = (credential_portal_url or "").rstrip("/") or None
        self._enum_ids: dict[str, dict[str, int]] = {}  # _ENUM_SOURCES kind -> resolved map
        self._enum_fetched_at: dict[str, float] = {}    # kind -> monotonic time of that fetch
        # Per-user attribution (Decision 5). When a resolver is wired, authorship
        # writes route through the caller's own Redmine key; project resolution and
        # issue-in-project verification always stay on the shared key.
        self._key_resolver = key_resolver
        self._enforce_personal = enforce_personal

    # --- public operations -------------------------------------------------

    def get(self, issue_id: str, context: RequestContext) -> dict[str, Any]:
        read_key, personal = self._read_key(context)  # fail-loud early (undecryptable/degraded)
        pid = self._resolve_project_id(context)
        issue = self._get_issue_in_project(issue_id, pid, api_key=read_key, personal=personal)
        # description rides on get() only -- the one issue a caller asked for -- and
        # not on the shared _normalize_issue that search/mine/create use for lists,
        # where a full description per item is bulk the caller rarely wants yet.
        result = _normalize_issue(issue)
        result["description"] = issue.get("description")
        return result

    def search(self, filters: dict[str, Any], limit: int, context: RequestContext) -> dict[str, Any]:
        read_key, personal = self._read_key(context)  # fail-loud early (undecryptable/degraded)
        pid = self._resolve_project_id(context)
        params: dict[str, Any] = {"project_id": pid, "limit": max(1, min(limit, 100))}
        status = filters.get("status")
        if status is not None:
            params["status_id"] = self._status_filter(status)
        assignee = filters.get("assignee")
        if assignee is not None:
            params["assigned_to_id"] = assignee
        data = self._read("GET", "/issues.json", params=params, api_key=read_key, personal=personal)
        issues = data.get("issues") if isinstance(data, dict) else None
        if not isinstance(issues, list):
            issues = []
        # Defense-in-depth: do not trust the backend's project filter — verify each
        # item belongs to the resolved project and drop anything else.
        scoped: list[dict[str, Any]] = []
        for item in issues:
            if not isinstance(item, dict):
                continue
            if _d(item.get("project")).get("id") != pid:
                continue
            scoped.append(_normalize_issue(item))
            if len(scoped) >= limit:
                break
        return {"issues": scoped, "count": len(scoped)}

    def create(self, fields: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        write_key, personal = self._write_key(context)  # fail-loud early (enforced/undecryptable)
        pid = self._resolve_project_id(context)
        issue_body: dict[str, Any] = {"project_id": pid, "subject": fields["subject"]}
        issue_body["description"] = _with_attribution(fields.get("description"), context, personal=personal)
        if fields.get("tracker") is not None:
            issue_body["tracker_id"] = self._enum_id("tracker", fields["tracker"])
        elif fields.get("tracker_id") is not None:
            issue_body["tracker_id"] = fields["tracker_id"]
        if fields.get("assignee") is not None:
            issue_body["assigned_to_id"] = fields["assignee"]
        self._apply_planning(issue_body, pid, fields, api_key=write_key, personal=personal)
        data = self._mutate("POST", "/issues.json", {"issue": issue_body}, api_key=write_key, personal=personal)
        issue = data.get("issue") if isinstance(data, dict) else None
        if not isinstance(issue, dict) or "id" not in issue:
            raise IssueBackendError("issue tracker returned an unexpected create response")
        # Fail closed if the backend created (or reports) the issue in another project.
        if _d(issue.get("project")).get("id") != pid:
            raise IssueBackendError("created issue is not in the expected project")
        result = _normalize_issue(issue)
        result["created"] = True
        return result

    def add_note(self, issue_id: str, note: str, context: RequestContext) -> dict[str, Any]:
        write_key, personal = self._write_key(context)  # fail-loud early
        pid = self._resolve_project_id(context)
        # On the WRITER's key, not the shared one: the check standing in front of
        # the write must see what the write will see, or writes stay gated on the
        # service account's memberships.
        self._get_issue_in_project(issue_id, pid, api_key=write_key, personal=personal)
        body_note = _with_attribution(note, context, personal=personal)
        self._mutate(
            "PUT", f"/issues/{_issue_path(issue_id)}.json",
            {"issue": {"notes": body_note}}, api_key=write_key, personal=personal,
        )
        return {"noted": True, "id": str(issue_id)}

    def update_status(
        self, issue_id: str, status: str, done_ratio: int | None, context: RequestContext,
        *, assignee: str | None = None, planning: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        write_key, personal = self._write_key(context)  # fail-loud early, before any network
        normalized = _normalize_status(status)
        status_id = self._enum_id("status", status)
        pid = self._resolve_project_id(context)
        # On the WRITER's key -- see add_note.
        self._get_issue_in_project(issue_id, pid, api_key=write_key, personal=personal)
        issue_body: dict[str, Any] = {"status_id": status_id, "notes": _attribution(context, personal=personal)}
        if done_ratio is not None:
            issue_body["done_ratio"] = done_ratio
        if assignee is not None:
            issue_body["assigned_to_id"] = assignee
        self._apply_planning(issue_body, pid, planning or {}, api_key=write_key, personal=personal)
        self._mutate(
            "PUT", f"/issues/{_issue_path(issue_id)}.json",
            {"issue": issue_body}, api_key=write_key, personal=personal,
        )
        return {"updated": True, "id": str(issue_id), "status": normalized}

    def categories(self, context: RequestContext) -> dict[str, Any]:
        """This project's issue categories (id + name), fetched live.

        Not cached, unlike the _ENUM_SOURCES vocabularies: categories are
        per-project and editable by ordinary project members, so a cache would
        serve a stale list right after someone adds one. The shared key is enough
        (reading category names is not an authorship action)."""
        pid = self._resolve_project_id(context)
        cats = self._fetch_categories(pid)
        return {"categories": [{"id": str(c["id"]), "name": c["name"]} for c in cats], "count": len(cats)}

    def mine(self, limit: int, context: RequestContext) -> dict[str, Any]:
        """Issues in this project assigned to the caller.

        Unlike _write_key there is no shared-key fallback at any setting:
        `assigned_to_id=me` on the shared service key resolves to the service
        account and would return *its* issues as if they were the caller's. That is
        a wrong answer, not a degraded one, so this fails loud regardless of
        enforce_personal — that flag governs write attribution, while this is a read
        whose entire meaning is the caller's identity."""
        hint = _enrollment_hint(self._portal_url)
        if self._key_resolver is None:
            raise IssueBackendError(
                "issues.mine needs your personal Redmine key, and this gateway has no key store "
                "configured" + hint,
                status=428,
            )
        state, personal = self._key_resolver(context.actor)
        if state is KeyState.DEGRADED:
            raise IssueBackendError(
                "the credential store is temporarily unusable, so the gateway cannot tell which issues "
                "are yours; answering from the shared account would return its issues as if they were "
                "yours. Re-enrolling is not the fix and would be refused -- operators can see it "
                "on /healthz",
                status=503,
            )
        if state is KeyState.UNDECRYPTABLE:
            raise IssueBackendError(
                "your personal Redmine key could not be decrypted (the keystore may have been rotated); "
                "please re-enroll it via the gateway's credential-enrollment endpoint" + hint,
                status=409,
            )
        if state is not KeyState.OK or not personal:
            raise IssueBackendError(
                "issues.mine needs your personal Redmine key to tell which issues are yours — the shared "
                "service key cannot stand in for you; enroll it via the gateway's credential-enrollment "
                "endpoint and try again" + hint,
                status=428,
            )
        return self.list_assigned_to_me(personal, context, limit)

    def verify_key(self, plaintext: str) -> dict[str, Any]:
        """Confirm a submitted Redmine key is valid and return its owner.

        Calls ``/users/current.json`` with the key (header-only — never in the URL,
        which would leak it into Redmine's access log). Used at set-time so the
        portal can bind key ownership to the SSO identity (email match)."""
        data = self._request("GET", "/users/current.json", api_key=plaintext)
        user = data.get("user") if isinstance(data, dict) else None
        if not isinstance(user, dict):
            raise IssueBackendError("could not verify redmine key", status=401)
        return {"id": user.get("id"), "login": user.get("login"), "mail": user.get("mail")}

    def list_assigned_to_me(self, personal_key: str, context: RequestContext, limit: int = 25) -> dict[str, Any]:
        """Issues in the caller's project assigned to *them*, using their own key.

        ``assigned_to_id=me`` resolves to the personal key's owner, so this must run
        on the personal key (never the shared service key, or ``me`` would resolve to
        the service account — see the fail-closed gate in the caller)."""
        pid = self._resolve_project_id(context)  # shared key ok (non-authorship)
        params: dict[str, Any] = {"project_id": pid, "assigned_to_id": "me", "limit": max(1, min(limit, 100))}
        data = self._request("GET", "/issues.json", params=params, api_key=personal_key)
        issues = data.get("issues") if isinstance(data, dict) else None
        if not isinstance(issues, list):
            issues = []
        scoped: list[dict[str, Any]] = []
        for item in issues:
            if not isinstance(item, dict):
                continue
            if _d(item.get("project")).get("id") != pid:  # defense-in-depth project re-filter
                continue
            scoped.append(_normalize_issue(item))
            if len(scoped) >= limit:
                break
        return {"issues": scoped, "count": len(scoped)}

    # --- internals ---------------------------------------------------------

    def _read(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        api_key: str | None,
        personal: bool,
    ) -> dict[str, Any]:
        """_mutate's counterpart for reads: translate the caller's own key's failures.

        Called for EVERY read, shared-key ones included. What is conditional is the
        TRANSLATION: on the shared key a 401/403 means the SERVICE ACCOUNT lacks
        access, an operator problem the caller cannot fix, so those keep the
        untranslated message."""
        try:
            return self._request(method, path, params=params, api_key=api_key)
        except IssueBackendError as exc:
            if personal and exc.status == 401:
                raise IssueBackendError(
                    "your personal Redmine key is invalid or was revoked; please re-enroll it via the "
                    "gateway's credential-enrollment endpoint" + _enrollment_hint(self._portal_url),
                    status=401,
                ) from exc
            if personal and exc.status == 403:
                # Reached from a WRITE too (the gating reads in add_note /
                # update_status / create), so the text must not name an operation.
                #
                # Disclosure boundary: what the gateway discloses is a SUBSET of what
                # the caller's own tracker account discloses to them directly -- a
                # non-member asking the tracker for an issue in that project gets this
                # same 403 from the tracker itself. One case does change, and it is the
                # cost of the fix: an issue in ANOTHER project that the shared key can
                # read but the caller's cannot used to return the uniform "issue not
                # found" and now returns this 403, so for that one combination
                # cross-project existence became distinguishable. Mapping it back to
                # 404 is rejected -- it cannot be done selectively (a 403 withholds the
                # project, so a foreign issue is indistinguishable from an in-project
                # one) and it would destroy the only message that names the actual,
                # fixable cause.
                raise IssueBackendError(
                    "your tracker account has no access in this project (check that you are a member "
                    "of it)",
                    status=403,
                ) from exc
            raise

    def _read_key(self, context: RequestContext) -> tuple[str | None, bool]:
        """Pick the key for a non-authorship READ: (key, is_personal).

        MEASURED failure this fixes: reads ran on the shared service key, so the
        gateway's reach was the SERVICE ACCOUNT's project memberships, which have
        nothing to do with the caller's. Both directions were wrong -- a member of
        a project the service account cannot see got a bare `issue tracker HTTP
        403` from issues.get while their own account could open the same issue in
        the tracker's web UI, and a non-member could read issues their own account
        could not, because the token's project claim was the only gate.

        MISSING falls back to the shared key: reads stay available to anyone who
        has not enrolled, which is why enrolment is optional at all.

        UNDECRYPTABLE fails loud for that user only, exactly as _write_key does.
        Falling back there would silently change WHICH issues the answer covers,
        and a wrong answer is worse than an error that names its own fix.

        DEGRADED fails closed for the same reason, and it is what the first
        version of this method got wrong: the keystore reported a master-key
        outage as MISSING, so every ENROLLED caller's reads silently reverted to
        the shared credential's visibility -- reintroducing the exact defect this
        method exists to remove. 503, not the 409 UNDECRYPTABLE uses: re-enrolling
        is not the fix and would itself be refused (KeyStore.set raises while
        degraded), so 409's "please re-enroll" text would send the caller into a
        wall. Writes deliberately still fall back here -- a write on the shared
        account is degraded but honest, because the attribution footer names the
        real actor. No footer can fix a wrong set of rows."""
        if self._key_resolver is None:
            return self._api_key, False
        state, personal = self._key_resolver(context.actor)
        if state is KeyState.OK and personal:
            return personal, True
        if state is KeyState.DEGRADED:
            raise IssueBackendError(
                "the credential store is temporarily unusable; this read is blocked rather than "
                "answered from the shared account, which would return a different set of issues. "
                "This is a server-side condition -- re-enrolling is not the fix and would be "
                "refused; operators can see it on /healthz",
                status=503,
            )
        if state is KeyState.UNDECRYPTABLE:
            raise IssueBackendError(
                "your personal Redmine key could not be decrypted (the keystore may have been rotated); "
                "please re-enroll it via the gateway's credential-enrollment endpoint"
                + _enrollment_hint(self._portal_url),
                status=409,
            )
        return self._api_key, False

    def _write_key(self, context: RequestContext) -> tuple[str | None, bool]:
        """Pick the key for an *authorship* write: (key, is_personal), or fail loud.

        Only the mutating call routes through here. MISSING falls back to the shared
        key in optional mode, or fails loud in enforced mode (Decision 5/B). An
        UNDECRYPTABLE record always fails loud for that user only (never a silent
        degrade to the shared account)."""
        if self._key_resolver is None:
            # No key store wired. In enforced mode this is a misconfiguration, not a
            # licence to silently attribute writes to the shared account — fail loud.
            if self._enforce_personal:
                raise IssueBackendError("enforced personal-key mode requires a key store", status=428)
            return self._api_key, False
        state, personal = self._key_resolver(context.actor)
        if state is KeyState.OK and personal:
            return personal, True
        if state is KeyState.UNDECRYPTABLE:
            raise IssueBackendError(
                "your personal Redmine key could not be decrypted (the keystore may have been rotated); "
                "please re-enroll it via the gateway's credential-enrollment endpoint"
                + _enrollment_hint(self._portal_url),
                status=409,
            )
        if state is KeyState.DEGRADED and self._enforce_personal:
            # Enforced mode promised writes carry the caller's own key; while the
            # store is degraded it cannot, and falling back would break that
            # promise silently. Optional mode still falls back below: a write on
            # the shared account is degraded but honest, because the attribution
            # footer names the real actor.
            raise IssueBackendError(
                "the credential store is temporarily unusable and this gateway enforces personal-key "
                "writes; re-enrolling is not the fix and would be refused -- operators can see it "
                "on /healthz",
                status=503,
            )
        if self._enforce_personal:
            raise IssueBackendError(
                "this operation needs your personal Redmine key; enroll it via the gateway's "
                "credential-enrollment endpoint and try again" + _enrollment_hint(self._portal_url),
                status=428,
            )
        return self._api_key, False

    def _mutate(
        self, method: str, path: str, body: dict[str, Any], *, api_key: str | None, personal: bool
    ) -> dict[str, Any]:
        try:
            return self._request(method, path, body=body, api_key=api_key)
        except IssueBackendError as exc:
            if personal and exc.status == 401:
                raise IssueBackendError(
                    "your personal Redmine key is invalid or was revoked; please re-enroll it via "
                    "the gateway's credential-enrollment endpoint" + _enrollment_hint(self._portal_url),
                    status=401,
                ) from exc
            if personal and exc.status == 403:
                raise IssueBackendError("your Redmine account has no write access to this project (confirm you are a member of it)", status=403) from exc
            raise

    def _resolve_project_id(self, context: RequestContext) -> int:
        key = context.issue_project
        if not key:
            # Policy denies issue tools without an issue_project, so this is a guard.
            raise IssueBackendError("token has no redmine project")
        if key in self._project_id_cache:
            return self._project_id_cache[key]
        data = self._request("GET", f"/projects/{_issue_path(key)}.json")
        project = data.get("project") if isinstance(data, dict) else None
        pid = project.get("id") if isinstance(project, dict) else None
        if not isinstance(pid, int):
            raise IssueBackendError("could not resolve redmine project")
        self._project_id_cache[key] = pid
        return pid

    def _enum_map(self, kind: str, *, refresh: bool = False) -> dict[str, int]:
        """Normalized name -> this instance's id, for one of _ENUM_SOURCES. Cached;
        these vocabularies are instance-global and change only when an admin edits
        them."""
        fetched_at = self._enum_fetched_at.get(kind)
        expired = fetched_at is None or (time.monotonic() - fetched_at) >= _ENUM_CACHE_TTL_SEC
        if kind not in self._enum_ids or refresh or expired:
            path, key = _ENUM_SOURCES[kind]
            data = self._request("GET", path)
            rows = data.get(key) if isinstance(data, dict) else None
            resolved: dict[str, int] = {}
            for row in rows if isinstance(rows, list) else []:
                if not isinstance(row, dict) or not isinstance(row.get("id"), int):
                    continue
                name = _normalize_status(row.get("name"))
                if name and name not in resolved:
                    resolved[name] = row["id"]
            if not resolved:
                raise IssueBackendError(f"could not resolve this issue tracker's {kind} list")
            self._enum_ids[kind] = resolved
            self._enum_fetched_at[kind] = time.monotonic()
        return self._enum_ids[kind]

    def _lookup_enum(self, kind: str, normalized: str) -> int | None:
        """Cached lookup, refetching once on a miss: a value an admin adds while the
        process is up must become usable without a restart."""
        for refresh in (False, True):
            values = self._enum_map(kind, refresh=refresh)
            if normalized in values:
                return values[normalized]
        return None

    def _enum_id(self, kind: str, requested: Any) -> int:
        resolved = self._lookup_enum(kind, _normalize_status(requested))
        if resolved is None:
            raise ValueError(
                f"unknown {kind} '{requested}' on this issue tracker; "
                f"allowed: {', '.join(sorted(self._enum_map(kind)))}"
            )
        return resolved

    def _status_filter(self, status: Any) -> Any:
        if isinstance(status, str):
            if status.lower() in _STATUS_FILTER_PASSTHROUGH:
                return status.lower()
            status_id = self._lookup_enum("status", _normalize_status(status))
            if status_id is not None:
                return status_id
            # Same failure as the write path: name what this instance offers. A bare
            # "unknown status filter" left the caller with nothing to correct.
            raise ValueError(
                f"unknown status filter '{status}'; allowed: "
                f"{', '.join(sorted(self._enum_map('status')))}, "
                f"or {' / '.join(sorted(_STATUS_FILTER_PASSTHROUGH))}"
            )
        raise ValueError(f"unknown status filter '{status}'")

    def _apply_planning(
        self, issue_body: dict[str, Any], project_id: int, fields: dict[str, Any],
        *, api_key: str | None, personal: bool,
    ) -> None:
        """Optional planning fields shared by create and update_status.

        api_key/personal have no default for the same reason _get_issue_in_project
        does not: the parent check gates a write, so it must run on the key that
        will perform that write.

        The parent is resolved through the project-scoped read first: Redmine will
        happily parent an issue onto one from another project, which both crosses the
        tenant boundary and turns the field into an existence oracle for ids the
        caller may not read.
        """
        if fields.get("dueDate") is not None:
            issue_body["due_date"] = _due_date(fields["dueDate"])
        if fields.get("priority") is not None:
            issue_body["priority_id"] = self._enum_id("priority", fields["priority"])
        if fields.get("parentIssue") is not None:
            parent = fields["parentIssue"]
            self._get_issue_in_project(str(parent), project_id, api_key=api_key, personal=personal)
            issue_body["parent_issue_id"] = int(parent)
        if fields.get("category") is not None:
            issue_body["category_id"] = self._category_id(project_id, str(fields["category"]))

    def _fetch_categories(self, project_id: int) -> list[dict[str, Any]]:
        data = self._request("GET", f"/projects/{project_id}/issue_categories.json")
        cats = data.get("issue_categories") if isinstance(data, dict) else None
        return [c for c in cats if isinstance(c, dict) and c.get("id") is not None] if isinstance(cats, list) else []

    def _category_id(self, project_id: int, name: str) -> int:
        cats = self._fetch_categories(project_id)
        for c in cats:
            if str(c.get("name", "")).lower() == name.lower():
                return int(c["id"])
        available = ", ".join(sorted(str(c.get("name")) for c in cats)) or "(none configured)"
        raise ValueError(f"unknown category '{name}' for this project; allowed: {available}")

    def _get_issue_in_project(
        self, issue_id: str, project_id: int, *, api_key: str | None, personal: bool
    ) -> dict[str, Any]:
        # No default, deliberately. A default of "shared" is how the write path
        # kept gating writes on the SERVICE ACCOUNT's memberships after reads were
        # fixed; every call site must now say which key it means.
        data = self._read(
            "GET", f"/issues/{_issue_path(issue_id)}.json", api_key=api_key, personal=personal
        )
        issue = data.get("issue") if isinstance(data, dict) else None
        if not isinstance(issue, dict):
            raise IssueBackendError("issue not found", status=404)
        if _d(issue.get("project")).get("id") != project_id:
            # Do not reveal that the issue exists in another project.
            raise IssueBackendError("issue not found", status=404)
        return issue

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        api_key: str | None = None,
    ) -> dict[str, Any]:
        url = parse.urljoin(self._base_url + "/", path.lstrip("/"))
        if params:
            url = f"{url}?{parse.urlencode(params)}"
        headers = {"Accept": "application/json"}
        # Explicit api_key routes authorship writes / me-reads through the caller's
        # personal key; the default (None) uses the shared service key for everything
        # non-authorship (project resolve, issue-in-project verify, general reads).
        key = api_key if api_key is not None else self._api_key
        if key:
            headers["X-Redmine-API-Key"] = key
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
        except (OSError, http.client.HTTPException, ValueError) as exc:
            # A garbled or truncated reply is an HTTPException, not an OSError, and
            # a credential or redirect the request cannot be encoded with is a
            # ValueError; either way the backend is unusable, not the caller.
            raise IssueBackendError("issue tracker unavailable") from exc

        if len(raw) > _MAX_RESPONSE_BYTES:
            raise IssueBackendError("issue tracker response too large")
        if not raw:
            return {}
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise IssueBackendError("issue tracker returned invalid JSON") from exc
        if not isinstance(decoded, dict):
            return {}
        return decoded


def _issue_path(value: Any) -> str:
    # path segment used in a Redmine URL; allow only safe id/identifier characters
    text = str(value).strip()
    if not text or any(c in text for c in "/?#%& "):
        raise ValueError("invalid issue or project reference")
    return text


def _normalize_issue(issue: dict[str, Any]) -> dict[str, Any]:
    project = _d(issue.get("project"))
    assigned = _d(issue.get("assigned_to"))
    assignee = None
    if assigned.get("id") is not None:
        assignee = {"id": str(assigned.get("id")), "displayName": assigned.get("name")}
    return {
        "id": str(issue.get("id", "")),
        "projectId": str(project.get("id", "")),
        "projectName": project.get("name"),
        "subject": issue.get("subject"),
        "status": _normalize_status(_d(issue.get("status")).get("name")),
        "tracker": _normalize_status(_d(issue.get("tracker")).get("name")),
        "category": _d(issue.get("category")).get("name"),
        "assignee": assignee,
        "doneRatio": issue.get("done_ratio"),
        "updatedAt": issue.get("updated_on"),
    }
