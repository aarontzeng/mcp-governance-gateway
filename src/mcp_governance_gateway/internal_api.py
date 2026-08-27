from __future__ import annotations

from collections import deque
import threading
import time
import uuid

from .audit import AuditEvent, AuditSink
from .auth import Principal
from .issue_backend import IssueBackend, IssueBackendError
from .memory_backend import RequestContext
from .redmine_keystore import KeyState, KeyStoreError, RedmineKeyStore


def _norm_email(value: object) -> str:
    return value.strip().lower() if isinstance(value, str) else ""


class _ActorRateLimiter:
    """Per-actor sliding-window limiter for the credential-write endpoint."""

    def __init__(self, per_minute: int) -> None:
        self._per_minute = per_minute
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = {}

    def allow(self, actor: str) -> bool:
        if self._per_minute <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            dq = self._hits.setdefault(actor, deque())
            cutoff = now - 60
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if len(dq) >= self._per_minute:
                return False
            dq.append(now)
            return True


class InternalApi:
    """Portal-facing internal endpoints, not part of the MCP tool surface.

    Every call is authenticated by the caller's own per-user bearer token and acts
    strictly on that token's actor (never a client-supplied identity, and the
    identity-propagation override is deliberately NOT applied on this path). Writes
    are audited and rate-limited. Even if the front gateway ever exposed this path,
    a caller could still only manage *their own* key with a Redmine key that
    validates as *their own* email.
    """

    def __init__(
        self,
        keystore: RedmineKeyStore | None,
        issue_backend: IssueBackend | None,
        audit_sink: AuditSink,
        writes_per_minute: int = 10,
        reads_per_minute: int = 60,
        backend_name: str = "redmine",
    ) -> None:
        self._keystore = keystore
        self._issues = issue_backend
        self._audit = audit_sink
        # Which issue backend this deployment runs (ADR-0013): enrolled credentials
        # are bound to it in the store, and status/my-issues read the same slot.
        self._backend_name = backend_name
        self._limiter = _ActorRateLimiter(writes_per_minute)
        self._read_limiter = _ActorRateLimiter(reads_per_minute)

    def _emit(self, principal: Principal, tool: str, outcome: str, reason: str = "", resource_id: str | None = None) -> None:
        self._audit.write(
            AuditEvent(
                request_id=str(uuid.uuid4()),
                actor=principal.actor,
                project=principal.project,
                tool=tool,
                decision="allow",
                outcome=outcome,
                reason=reason,
                resource_id=resource_id,
            )
        )

    def status(self, principal: Principal) -> tuple[int, dict]:
        if self._keystore is None:
            return 200, {"enabled": False, "hasKey": False}
        st = self._keystore.status(principal.actor, backend=self._backend_name)
        st["enabled"] = True
        return 200, st

    def set_key(self, principal: Principal, plaintext: object) -> tuple[int, dict]:
        if self._keystore is None:
            return 404, {"error": "personal key store not configured"}
        if not isinstance(plaintext, str) or not plaintext.strip():
            return 400, {"error": "key required"}
        plaintext = plaintext.strip()
        if len(plaintext) > 256:
            return 400, {"error": "key too long"}
        if not self._limiter.allow(principal.actor):
            self._emit(principal, "redmine.key.set", "rate_limited")
            return 429, {"error": "too many attempts, try again shortly"}
        if self._keystore.degraded:
            self._emit(principal, "redmine.key.set", "degraded", "keystore master key unavailable")
            return 503, {"error": "key store unavailable"}
        if self._issues is None:
            return 503, {"error": "issue backend not configured"}
        # Bind ownership: the submitted key must resolve to *this* SSO user's email.
        try:
            user = self._issues.verify_key(plaintext)
        except IssueBackendError:
            self._emit(principal, "redmine.key.set", "invalid_key")
            return 400, {"error": "Redmine key invalid or Redmine unreachable"}
        want = _norm_email(principal.email)
        got = _norm_email(user.get("mail"))
        if not want or not got or want != got:
            self._emit(principal, "redmine.key.set", "identity_mismatch")
            return 403, {"error": "this key belongs to a different Redmine user"}
        try:
            self._keystore.set(principal.actor, plaintext, user.get("login"), backend=self._backend_name)
        except KeyStoreError:
            self._emit(principal, "redmine.key.set", "store_error")
            return 503, {"error": "key store unavailable"}
        self._emit(principal, "redmine.key.set", "ok", resource_id=user.get("login"))
        return 200, {"ok": True, "redmineLogin": user.get("login")}

    def clear_key(self, principal: Principal) -> tuple[int, dict]:
        if self._keystore is None:
            return 404, {"error": "personal key store not configured"}
        cleared = self._keystore.clear(principal.actor)
        self._emit(principal, "redmine.key.clear", "ok" if cleared else "noop")
        return 200, {"ok": True, "cleared": cleared}

    def my_issues(self, principal: Principal) -> tuple[int, dict]:
        # Fail closed: only query with a usable personal key. Without one, `me` would
        # resolve to the shared service account and leak its issues as "yours".
        if self._keystore is None or self._issues is None or not principal.issue_project:
            return 200, {"hasKey": False, "issues": []}
        state, key = self._keystore.get(principal.actor, backend=self._backend_name)
        if state is not KeyState.OK or not key:
            return 200, {"hasKey": False, "issues": []}
        if not self._read_limiter.allow(principal.actor):
            return 200, {"hasKey": True, "issues": [], "error": "rate_limited"}
        context = RequestContext.from_principal(principal, str(uuid.uuid4()))
        try:
            result = self._issues.list_assigned_to_me(key, context)
        except IssueBackendError as exc:
            return 200, {"hasKey": True, "issues": [], "error": str(exc.status or "error")}
        return 200, {"hasKey": True, "issues": result.get("issues", [])}
