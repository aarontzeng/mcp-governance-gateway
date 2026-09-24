from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .hotfile import ReloadingFile


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


@dataclass(frozen=True)
class _TokenIndex:
    """The token map, and the same map keyed by each token's SHA-256.

    Authentication compared the presented bearer against every token in turn --
    linear in the store, 0.1 ms per request at a thousand tokens and 0.5 ms at
    five thousand, measured. A digest lookup is constant. It does not trade away
    the constant-time property the scan had: an attacker controls the bearer but
    not its digest, so the lookup's timing says nothing about any stored token,
    and the one candidate found is still compared in constant time."""

    claims: dict[str, Principal]
    by_digest: dict[bytes, tuple[bytes, Principal]]

    @classmethod
    def build(cls, claims: dict[str, Principal]) -> _TokenIndex:
        by_digest = {}
        for token, principal in claims.items():
            raw = token.encode("utf-8")
            by_digest[hashlib.sha256(raw).digest()] = (raw, principal)
        return cls(claims, by_digest)


class BearerTokenAuthenticator:
    def __init__(
        self,
        token_claims: dict[str, Principal],
        sources: list[tuple[Path, bool]] | None = None,
    ) -> None:
        # sources: (path, required). When set, the token maps are reloaded on file
        # change so tokens minted at runtime (e.g. per-user tokens) take effect
        # without an adapter restart. Empty -> static (tests / no hot-reload).
        # A corrupt or missing file keeps the last-good map (a bad write must
        # never lock everyone out) and says so, loudly: a revoke written into a
        # corrupt file has NOT taken effect. hotfile.ReloadingFile owns that
        # policy; `_load_all` is looked up at call time because a test patches it.
        #
        # The file is stat'd on every request (about 1.4 us, measured) rather than
        # on a timer: a timer would save that and make every revocation wait for it.
        self._sources = sources or []
        self._store: ReloadingFile[_TokenIndex] = ReloadingFile(
            [path for path, _ in self._sources],
            lambda previous: _TokenIndex.build(self._load_all(self._sources)),
            what="token file",
            initial=_TokenIndex.build(token_claims),
            failure_message="token file reload failed; keeping the last-good token set",
        )

    @property
    def _token_claims(self) -> dict[str, Principal]:
        """The live map, WITHOUT checking the file -- for observing the state a
        reload published rather than repairing it with another reload."""
        return self._store.value.claims

    @classmethod
    def from_file(cls, path: str | Path) -> BearerTokenAuthenticator:
        return cls.from_files([(path, True)])

    @classmethod
    def from_files(cls, sources: list[tuple[str | Path, bool]],
                   allow_empty: bool = False) -> BearerTokenAuthenticator:
        """`allow_empty` is for a deployment whose identities come from elsewhere.

        The empty-merge guard exists to catch a misconfigured token store, which
        is the right default. It is wrong for an OIDC deployment that also names
        a runtime store: that file is legitimately empty until the first token is
        minted into it, and refusing to boot over it would make configuring both
        paths a startup failure.
        """
        norm = [(Path(p), bool(required)) for p, required in sources]
        merged = cls._merge_sources(norm)
        if not merged and not allow_empty:
            raise ValueError("no tokens loaded from any source")
        return cls(merged, sources=norm)

    @staticmethod
    def _merge_sources(sources: list[tuple[Path, bool]]) -> dict[str, Principal]:
        merged: dict[str, Principal] = {}
        for path, required in sources:
            merged.update(_load_token_claims(path, required=required))
        return merged

    @staticmethod
    def _load_all(sources: list[tuple[Path, bool]]) -> dict[str, Principal]:
        """The RELOAD path, whose emptiness rule is not the startup one.

        An empty merge here raises so `_maybe_reload` keeps the last-good map: a
        botched write must never lock everyone out, and that is true whether or
        not the deployment also has an IdP. Startup is the different case -- a
        runtime store is legitimately empty before the first token is minted --
        so `from_files` applies its own policy and this stays one-argument,
        which is also the seam the reload-ordering test patches.
        """
        merged = BearerTokenAuthenticator._merge_sources(sources)
        if not merged:
            raise ValueError("no tokens loaded from any source")
        return merged

    def _maybe_reload(self) -> None:
        self._store.refresh()

    def authenticate_header(self, authorization: str | None) -> Principal:
        self._maybe_reload()
        if not authorization:
            raise AuthError("missing authorization")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise AuthError("invalid authorization")

        # Bytes, not str: http.server decodes headers as latin-1, and a non-ASCII
        # bearer must be a 401, never a TypeError out of compare_digest (a 500).
        token_b = token.encode("utf-8")
        found = self._store.value.by_digest.get(hashlib.sha256(token_b).digest())
        if found is not None and hmac.compare_digest(found[0], token_b):
            return found[1]
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
            f"{user_id}:{email}".encode(),
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
