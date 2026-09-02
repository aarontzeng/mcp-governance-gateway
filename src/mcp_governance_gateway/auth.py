from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import sys
import threading
from pathlib import Path
from typing import Any, Callable


class AuthError(Exception):
    pass


@dataclass(frozen=True)
class Principal:
    actor: str
    project: str
    roles: tuple[str, ...]
    token_id: str
    # Tenant key for the issue tracker. Vendor-neutral: a project may be backed by
    # Redmine today and something else later. The token store's legacy field name
    # `redmine_project` is still read (see load) and exposed as a deprecated alias.
    issue_project: str | None = None
    # Lookup email from the token store (the minter records it alongside each
    # per-user token). Used server-side to bind a submitted Redmine key to the SSO
    # identity; never client-supplied. The identity-propagation override touches
    # only `actor`, so this stays the token's own email.
    email: str | None = None

    @property
    def redmine_project(self) -> str | None:
        """Deprecated alias for `issue_project` (kept while callers migrate)."""
        return self.issue_project


class BearerTokenAuthenticator:
    def __init__(
        self,
        token_claims: dict[str, Principal],
        sources: list[tuple[Path, bool]] | None = None,
    ) -> None:
        self._token_claims = token_claims
        # sources: (path, required). When set, the token maps are reloaded on file
        # change so tokens minted at runtime (e.g. per-user tokens) take effect
        # without an adapter restart. Empty -> static (tests / no hot-reload).
        self._sources = sources or []
        self._mtimes = self._current_mtimes()
        self._reload_lock = threading.Lock()

    @classmethod
    def from_file(cls, path: str | Path) -> "BearerTokenAuthenticator":
        return cls.from_files([(path, True)])

    @classmethod
    def from_files(cls, sources: list[tuple[str | Path, bool]]) -> "BearerTokenAuthenticator":
        norm = [(Path(p), bool(required)) for p, required in sources]
        return cls(cls._load_all(norm), sources=norm)

    @staticmethod
    def _load_all(sources: list[tuple[Path, bool]]) -> dict[str, Principal]:
        merged: dict[str, Principal] = {}
        for path, required in sources:
            merged.update(_load_token_claims(path, required=required))
        if not merged:
            raise ValueError("no tokens loaded from any source")
        return merged

    def _current_mtimes(self) -> tuple:
        # Key on (st_mtime_ns, st_size, st_ino), not float mtime alone: os.replace swaps
        # in a new inode on every write, so st_ino makes an atomic swap detectable even on
        # coarse-mtime filesystems where two same-second writes share an mtime — otherwise a
        # revoke landing in the same tick as a mint could be missed and stay authenticating.
        out = []
        for path, _ in self._sources:
            try:
                st = path.stat()
                out.append((str(path), st.st_mtime_ns, st.st_size, st.st_ino))
            except OSError:
                out.append((str(path), None, None, None))
        return tuple(out)

    def _maybe_reload(self) -> None:
        if not self._sources:
            return
        if self._current_mtimes() == self._mtimes:
            return
        # Reloads are serialized, and the stat is repeated under the lock: two
        # requests that both saw a changed file would otherwise each load it, and
        # the one that loaded the OLDER version could publish last -- briefly
        # re-admitting a token the newer version revoked. Reads take no lock:
        # _load_all builds a fresh dict and we rebind (never mutate the live map in
        # place), so a concurrent authenticate always sees a complete map.
        with self._reload_lock:
            current = self._current_mtimes()
            if current == self._mtimes:
                return
            try:
                self._token_claims = self._load_all(self._sources)
            except Exception as exc:
                # keep the last-good token map on a missing/partial/corrupt file so a bad
                # write can never lock everyone out; retry on the next file change. Say so
                # loudly: a revoke written into a corrupt file has NOT taken effect.
                print(f"token file reload failed; keeping the last-good token set: {exc}", file=sys.stderr, flush=True)
            self._mtimes = current

    def authenticate_header(self, authorization: str | None) -> Principal:
        self._maybe_reload()
        if not authorization:
            raise AuthError("missing authorization")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise AuthError("invalid authorization")

        # Compare as bytes: hmac.compare_digest on str raises TypeError for non-ASCII input
        # (http.server decodes headers as latin-1), which would surface as a 500, not a 401.
        token_b = token.encode("utf-8")
        for candidate, principal in self._token_claims.items():
            if hmac.compare_digest(candidate.encode("utf-8"), token_b):
                return principal
        raise AuthError("invalid token")


@dataclass(frozen=True)
class IdentityVerifier:
    """Verify a front gateway's signed identity-propagation headers.

    the front gateway forwards the authenticated end-user as ``{prefix}-Id`` /
    ``{prefix}-Email`` headers and, when claim signing is on, an
    ``{prefix}-Claims-Signature`` = HMAC-SHA256 hex over the payload
    ``"<user_id>:<email>"`` keyed by a secret shared with this adapter.

    The bearer token remains the authorization principal (project, roles,
    redmine_project). A verified propagated identity overrides only ``actor`` so
    audit and attribution name the real end-user instead of the shared service
    identity. The signature is what makes the second hop trustworthy: a request
    that carries identity headers without a valid signature is a forgery attempt
    and is rejected. Only ``user_id``/``email`` are integrity-protected by
    the front gateway, so nothing else from these headers is trusted.

    With no shared secret configured, propagation is disabled and the headers are
    ignored (bearer-only, backward compatible) — forged headers cannot take effect.
    """

    secret: str
    prefix: str = "X-Forwarded-User"

    def resolve(self, header_get: Callable[[str], str | None], base: Principal) -> Principal:
        if not self.secret:
            return base
        user_id = header_get(f"{self.prefix}-Id")
        signature = header_get(f"{self.prefix}-Claims-Signature")
        if not user_id and not signature:
            return base
        if not user_id or not signature:
            raise AuthError("incomplete identity propagation headers")
        email = header_get(f"{self.prefix}-Email") or ""
        expected = hmac.new(
            self.secret.encode("utf-8"),
            f"{user_id}:{email}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise AuthError("invalid identity claims signature")
        return replace(base, actor=user_id)


def _load_token_claims(path: Path, *, required: bool) -> dict[str, Principal]:
    """Parse one token file into a token->Principal map.

    ``required`` files must exist and hold a non-empty ``tokens`` list; optional
    files (e.g. the runtime-managed per-user token store) may be absent or empty.
    """
    if not path.exists():
        if required:
            raise ValueError(f"token file not found: {path}")
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    tokens = data.get("tokens")
    if not isinstance(tokens, list):
        if required:
            raise ValueError("token file must contain a 'tokens' list")
        return {}
    if required and not tokens:
        raise ValueError("token file must contain a non-empty 'tokens' list")

    token_claims: dict[str, Principal] = {}
    for entry in tokens:
        if not isinstance(entry, dict):
            raise ValueError("token entries must be objects")
        token = _required_str(entry, "token")
        actor = _required_str(entry, "actor")
        project = _required_str(entry, "project")
        roles_raw = entry.get("roles", [])
        if not isinstance(roles_raw, list) or not all(isinstance(role, str) for role in roles_raw):
            raise ValueError("token roles must be a list of strings")
        # Accept the new vendor-neutral name, falling back to the legacy one so
        # tokens minted before the rename keep working without a re-mint.
        issue_project_raw = entry.get("issue_project", entry.get("redmine_project"))
        if issue_project_raw is not None and not isinstance(issue_project_raw, (str, int)):
            raise ValueError("token issue_project must be a string or integer")
        issue_project = str(issue_project_raw) if issue_project_raw is not None else None
        email_raw = entry.get("email")
        email = email_raw.strip() if isinstance(email_raw, str) and email_raw.strip() else None
        token_claims[token] = Principal(
            actor=actor,
            project=project,
            roles=tuple(roles_raw),
            token_id=_token_id(token),
            issue_project=issue_project,
            email=email,
        )
    return token_claims


def _required_str(entry: dict[str, Any], key: str) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"token entry field '{key}' must be a non-empty string")
    return value


def _token_id(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
