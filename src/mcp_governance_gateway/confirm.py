from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Any, Callable

from .auth import Principal


class ConfirmationStore:
    """Single-use, short-lived confirmation tokens for non-destructive writes.

    ADR-0003: confirmation prevents accidental writes by honest clients; it is not
    an authorization boundary. Each confirmation is a random nonce bound to the
    full principal (actor, project, token id, redmine project), the tool, and the
    normalized arguments of one action — so a token cannot be reused by a different
    token or for a different Redmine project. It is valid only for a short TTL and
    **consumed on first successful verify**, so it cannot be replayed. State is
    in-process, lock-guarded for the threaded server, and bounded; pending
    confirmations are lost on restart (acceptable — they are short-lived).

    ``verify`` returns a *reason* alongside its verdict so an honest client can
    act on a failure instead of being told only that it failed. That is safe to
    reveal precisely because this is not an authorization boundary — with one
    deliberate exception, see ``verify``.
    """

    def __init__(
        self, ttl_sec: int = 300, clock: Callable[[], float] | None = None, max_entries: int = 10_000
    ) -> None:
        self._ttl = ttl_sec
        self._clock = clock or time.time
        self._max_entries = max_entries
        # nonce -> (identity_key, action_key, field_digests, expiry). identity_key is
        # checked BEFORE anything else is allowed to differ in the response: a caller
        # whose principal/tool don't match the entry must be indistinguishable from a
        # caller who guessed a nonce that was never issued at all (see verify()).
        self._pending: dict[str, tuple[str, str, dict[str, str], float]] = {}
        self._lock = threading.Lock()

    def _identity_key(self, principal: Principal, tool: str) -> str:
        parts = [principal.actor, principal.project, principal.token_id, principal.issue_project or "", tool]
        return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()

    @staticmethod
    def _field_digests(args: dict[str, Any]) -> dict[str, str]:
        """Per-argument short digests, so a mismatch can name WHICH argument moved
        instead of only that something did. Plain strings hash their raw utf-8 --
        deliberately the same formula the confirmation echo uses for long text, so
        the two sets of numbers line up and a caller can diff them by eye.

        Non-strings are type-tagged. Without that, `"1"` and `1` produced the same
        digest while the action key (which is JSON-canonical, and so does
        distinguish them) correctly changed -- leaving a rejection whose
        changed-argument list was empty, which is the one thing this method exists
        to prevent. Strings keep the untagged formula so the echo alignment holds."""
        out: dict[str, str] = {}
        for key, value in args.items():
            if isinstance(value, str):
                raw = value.encode("utf-8")
            else:
                canonical = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
                raw = f"{type(value).__name__}:{canonical}".encode("utf-8")
            out[key] = hashlib.sha256(raw).hexdigest()[:8]
        return out

    def _action_key(self, principal: Principal, tool: str, args: dict[str, Any]) -> str:
        canonical = json.dumps(args, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        parts = [
            principal.actor,
            principal.project,
            principal.token_id,
            principal.issue_project or "",
            tool,
            canonical,
        ]
        return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()

    def _prune(self, now: float) -> None:
        for nonce in [n for n, (_, _, _, exp) in self._pending.items() if exp <= now]:
            del self._pending[nonce]

    def issue(self, principal: Principal, tool: str, args: dict[str, Any]) -> str:
        now = self._clock()
        with self._lock:
            self._prune(now)
            if len(self._pending) >= self._max_entries:
                oldest = min(self._pending, key=lambda n: self._pending[n][3])
                del self._pending[oldest]
            nonce = secrets.token_urlsafe(18)
            self._pending[nonce] = (
                self._identity_key(principal, tool),
                self._action_key(principal, tool, args),
                self._field_digests(args),
                now + self._ttl,
            )
            return nonce

    def verify(self, principal: Principal, tool: str, args: dict[str, Any], provided: Any) -> tuple[bool, str | None]:
        """Returns (ok, reason). reason is None both on success and when no confirm
        was supplied at all (an ordinary first call, not a failed resolve attempt) --
        otherwise a short, caller-facing explanation of why the supplied
        confirmationId didn't resolve. Safe to reveal: per the class docstring this
        is not an authorization boundary, only accidental-write prevention for an
        honest client, so there is no reason to leave every failure looking like a
        fresh first call the way a bare bool does. The one exception is deliberate:
        a nonce that belongs to a DIFFERENT principal/tool must look identical to a
        nonexistent one (both "unknown or already-used") -- distinguishing them
        would let one tenant learn whether some other tenant's confirmation exists
        or recently expired, purely from a nonce they should never have been able
        to guess in the first place, but the whole point of this feature is to stop
        assuming that."""
        if provided is None:
            return False, None  # no confirm key at all -- an ordinary first call
        if not isinstance(provided, str) or not provided:
            return False, (
                "confirm was supplied but is empty or not a string — it must be the exact "
                "confirmationId string returned by the previous call"
            )
        with self._lock:
            entry = self._pending.get(provided)
            if entry is None:
                return False, "unknown or already-used confirmationId"
            identity_key, action_key, confirmed_fields, expiry = entry
            if not hmac.compare_digest(identity_key, self._identity_key(principal, tool)):
                return False, "unknown or already-used confirmationId"
            if expiry <= self._clock():
                del self._pending[provided]
                return False, f"confirmationId expired ({self._ttl}s TTL) — start over with a fresh call"
            if not hmac.compare_digest(action_key, self._action_key(principal, tool, args)):
                now_fields = self._field_digests(args)
                changed = ", ".join(
                    f"{k} (confirmed {confirmed_fields.get(k, 'absent')}, got {now_fields.get(k, 'absent')})"
                    for k in sorted(set(confirmed_fields) | set(now_fields))
                    if confirmed_fields.get(k) != now_fields.get(k)
                )
                return False, (
                    f"confirmationId is valid but these arguments changed since it was issued: {changed}. "
                    "Resend the ORIGINAL values byte-for-byte — not a regenerated or reformatted copy, and "
                    "not the truncated echo. Equal length with a different digest means the text was altered "
                    "character-for-character (typographic quotes, dashes, non-breaking spaces): diff your two "
                    "payloads rather than retrying the same way."
                )
            del self._pending[provided]  # single-use: consume so the token cannot be replayed
            return True, None
