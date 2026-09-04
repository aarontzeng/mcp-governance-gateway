"""OIDC bearer verification: a second authenticator beside the token file.

Why this exists. ADR-0007 requires a token's actor to be an **immutable id that
was verified at mint time, taken from a signed identity assertion rather than a
self-reported field** — and then put minting out of scope, which left every
adopter hand-writing a JSON token file. An OIDC access token is exactly the
assertion ADR-0007 describes, already signed by something whose whole job is
verifying who the holder is. Verifying it here is not a new trust model; it is
the existing one with the minter finally supplied.

What this deliberately does not do. It does not replace the opaque-token path:
both run side by side, the token file is consulted first, and a deployment that
sets no OIDC variables behaves exactly as it did in 0.1.0. It also does not take
tenancy from the token. An IdP knows who someone is; it does not know which
project of *this* gateway they may act in, and a `project` claim minted by a
third party would make the tenant boundary depend on that party's configuration.
Tenancy comes from a grants file this deployment owns (ADR-0016).

Two rules the verification will not bend on:

- **The algorithm comes from our allow-list, never from the token.** `alg: none`
  and every HMAC algorithm are refused before any key lookup. A JWKS holds
  *public* keys; accepting HS256 would let anyone who can read the JWKS sign a
  token with the key it publishes. This is the classic JWT bypass and it is worth
  the explicit refusal.
- **The audience is checked, and there is no default for it.** An issuer mints
  tokens for many audiences; accepting any of them would let a token issued for
  an unrelated client act on this gateway.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib import error, request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils as asym_utils

from .auth import AuthError, Principal

# A signed JWS this gateway will verify, mapped to (hash, kind). Anything absent
# from this table is refused by name before a key is looked up -- see the module
# docstring on why `none` and HS* are not oversights.
_ALGORITHMS: dict[str, tuple[Any, str]] = {
    "RS256": (hashes.SHA256(), "rsa"),
    "RS384": (hashes.SHA384(), "rsa"),
    "RS512": (hashes.SHA512(), "rsa"),
    "ES256": (hashes.SHA256(), "ec"),
    "ES384": (hashes.SHA384(), "ec"),
    "ES512": (hashes.SHA512(), "ec"),
}
_EC_CURVES = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}
# An access token is a header, and http.server reads a header into memory before
# we see it; this is the second bound, on what we are willing to parse.
_MAX_TOKEN_BYTES = 16_384
_MAX_JWKS_BYTES = 256_000
_JWKS_TIMEOUT_SEC = 5.0


def _b64url(segment: str) -> bytes:
    """Decode one base64url JWS segment.

    Rejects the padded and whitespace-tolerant spellings `urlsafe_b64decode` would
    otherwise accept: a token is a wire format with exactly one valid encoding, and
    a decoder that accepts several is a decoder two implementations can disagree
    about.
    """
    if not segment or any(c in segment for c in "=+/\n\r \t"):
        raise AuthError("malformed token encoding")
    pad = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + pad)
    except (ValueError, TypeError) as exc:
        raise AuthError("malformed token encoding") from exc


def _json_object(raw: bytes, what: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AuthError(f"malformed token {what}") from exc
    if not isinstance(value, dict):
        raise AuthError(f"malformed token {what}")
    return value


def looks_like_jws(token: str) -> bool:
    """Three non-empty dot-separated segments — the shape, not a claim of validity.

    Used only to decide *which* authenticator answers, never whether to trust
    anything. An opaque token that happens to have this shape is still resolved
    against the token file first (see CompositeAuthenticator).
    """
    parts = token.split(".")
    return len(parts) == 3 and all(parts)


# --- keys ----------------------------------------------------------------


def _public_key_from_jwk(jwk: dict[str, Any]):
    kty = jwk.get("kty")
    try:
        if kty == "RSA":
            n = int.from_bytes(_b64url(jwk["n"]), "big")
            e = int.from_bytes(_b64url(jwk["e"]), "big")
            return rsa.RSAPublicNumbers(e, n).public_key()
        if kty == "EC":
            curve = _EC_CURVES.get(jwk.get("crv"))
            if curve is None:
                return None
            x = int.from_bytes(_b64url(jwk["x"]), "big")
            y = int.from_bytes(_b64url(jwk["y"]), "big")
            return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    except (KeyError, ValueError, TypeError, AuthError):
        return None  # a malformed key in a JWKS disables that key, not the gateway
    return None


class JwksCache:
    """The issuer's public keys, cached, with last-good kept on a fetch failure.

    Same posture as the token file's hot reload (`auth.py`): an IdP that becomes
    unreachable must not revoke everyone. The cooldown is what stops an unknown
    `kid` — the shape a key rotation takes — from turning every request into an
    outbound fetch.
    """

    def __init__(self, jwks_url: str, ttl_sec: float = 600.0, refetch_cooldown_sec: float = 30.0,
                 opener: Callable[[str], bytes] | None = None) -> None:
        self._url = jwks_url
        self._ttl = ttl_sec
        self._cooldown = refetch_cooldown_sec
        self._open = opener or self._fetch
        self._lock = threading.Lock()
        self._keys: dict[str, Any] = {}
        self._fetched_at = 0.0
        self._last_attempt = 0.0

    def _fetch(self, url: str) -> bytes:
        req = request.Request(url, headers={"Accept": "application/json"}, method="GET")
        with request.urlopen(req, timeout=_JWKS_TIMEOUT_SEC) as response:
            return response.read(_MAX_JWKS_BYTES)

    def _load(self) -> None:
        raw = self._open(self._url)
        payload = _json_object(raw, "key set")
        entries = payload.get("keys")
        keys: dict[str, Any] = {}
        for jwk in entries if isinstance(entries, list) else []:
            if not isinstance(jwk, dict):
                continue
            if jwk.get("use") not in (None, "sig"):
                continue  # an encryption key is not a signing key
            key = _public_key_from_jwk(jwk)
            if key is None:
                continue
            kid = jwk.get("kid")
            keys[kid if isinstance(kid, str) and kid else ""] = key
        if not keys:
            raise ValueError("key set contains no usable signing key")
        self._keys = keys
        self._fetched_at = time.monotonic()

    def get(self, kid: str | None) -> Any:
        now = time.monotonic()
        with self._lock:
            stale = not self._keys or (now - self._fetched_at) > self._ttl
            unknown = bool(self._keys) and kid is not None and kid not in self._keys
            if (stale or unknown) and (now - self._last_attempt) > self._cooldown:
                self._last_attempt = now
                try:
                    self._load()
                except Exception as exc:  # noqa: BLE001 - any failure keeps last-good
                    # Loud, and non-fatal: a rotation we could not fetch fails the
                    # requests using the new kid, not every request.
                    print(f"OIDC key set fetch failed; keeping the last-good keys: {exc}",
                          file=sys.stderr, flush=True)
            if kid:
                return self._keys.get(kid)
            # No kid in the header: unambiguous only when the issuer publishes one key.
            return next(iter(self._keys.values())) if len(self._keys) == 1 else None


def _verify_signature(alg: str, key: Any, signing_input: bytes, signature: bytes) -> None:
    digest, kind = _ALGORITHMS[alg]
    try:
        if kind == "rsa":
            if not isinstance(key, rsa.RSAPublicKey):
                raise AuthError("token signature is not valid")
            key.verify(signature, signing_input, padding.PKCS1v15(), digest)
            return
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise AuthError("token signature is not valid")
        # JWS carries ECDSA as the fixed-width R||S pair; `cryptography` verifies DER.
        half = len(signature) // 2
        if half == 0 or len(signature) % 2:
            raise AuthError("token signature is not valid")
        r = int.from_bytes(signature[:half], "big")
        s = int.from_bytes(signature[half:], "big")
        key.verify(asym_utils.encode_dss_signature(r, s), signing_input, ec.ECDSA(digest))
    except InvalidSignature as exc:
        raise AuthError("token signature is not valid") from exc


# --- grants --------------------------------------------------------------


@dataclass(frozen=True)
class Grant:
    project: str
    issue_project: str | None
    roles: tuple[str, ...]


class GrantsFile:
    """`subject -> grant` and `group -> grant`, hot-reloaded like the token file.

    This is the tenancy decision, and it belongs to the deployment rather than to
    the IdP: see the module docstring. A subject that matches nothing gets no
    grant, which `Policy.decide` already refuses for want of a project — the
    fail-closed direction.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._subjects: dict[str, Grant] = {}
        self._groups: dict[str, Grant] = {}
        self._sig: object = object()
        self._reload(initial=True)

    def _current_sig(self) -> tuple | None:
        try:
            st = self._path.stat()
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size, st.st_ino)

    @staticmethod
    def _grant(spec: Any) -> Grant | None:
        if not isinstance(spec, dict):
            return None
        project = spec.get("project")
        if not isinstance(project, str) or not project.strip():
            return None
        roles = spec.get("roles")
        role_tuple = tuple(r for r in roles if isinstance(r, str) and r) if isinstance(roles, list) else ()
        issue_project = spec.get("issue_project")
        return Grant(
            project=project.strip(),
            issue_project=str(issue_project) if issue_project not in (None, "") else None,
            roles=role_tuple,
        )

    def _reload(self, initial: bool = False) -> None:
        sig = self._current_sig()
        if sig == self._sig:
            return
        with self._lock:
            if sig == self._sig:
                return
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("grants file must be a JSON object")
                subjects, groups = {}, {}
                for key, spec in (data.get("subjects") or {}).items():
                    grant = self._grant(spec)
                    if grant is not None:
                        subjects[str(key)] = grant
                for key, spec in (data.get("groups") or {}).items():
                    grant = self._grant(spec)
                    if grant is not None:
                        groups[str(key)] = grant
                self._subjects, self._groups = subjects, groups
            except Exception as exc:  # noqa: BLE001
                if initial:
                    raise
                # Keep the last-good mapping, exactly as the token file does, and say
                # so: a grant *removed* in a corrupt file has not taken effect.
                print(f"OIDC grants reload failed; keeping the last-good grants: {exc}",
                      file=sys.stderr, flush=True)
            self._sig = sig

    def resolve(self, subject: str, groups: tuple[str, ...]) -> Grant | None:
        """A subject's own grant, else the union of its groups' grants.

        Two groups naming two different projects is refused rather than resolved:
        picking one would make a tenant boundary depend on dict ordering, and a
        person in two teams is a question for the operator, not for this code.
        """
        self._reload()
        direct = self._subjects.get(subject)
        if direct is not None:
            return direct
        matched = [self._groups[g] for g in groups if g in self._groups]
        if not matched:
            return None
        projects = {g.project for g in matched}
        if len(projects) > 1:
            raise AuthError("ambiguous project grant")
        issue_projects = {g.issue_project for g in matched if g.issue_project}
        if len(issue_projects) > 1:
            raise AuthError("ambiguous project grant")
        roles = sorted({r for g in matched for r in g.roles})
        return Grant(
            project=matched[0].project,
            issue_project=next(iter(issue_projects), None),
            roles=tuple(roles),
        )


# --- the authenticator ---------------------------------------------------


class OidcAuthenticator:
    def __init__(
        self,
        issuer: str,
        audience: str,
        jwks: JwksCache,
        grants: GrantsFile,
        clock_skew_sec: float = 60.0,
        groups_claim: str = "groups",
        required_scope: str | None = None,
    ) -> None:
        if not issuer or not audience:
            raise ValueError("OIDC needs both an issuer and an audience")
        self._issuer = issuer
        self._audience = audience
        self._jwks = jwks
        self._grants = grants
        self._skew = max(0.0, clock_skew_sec)
        self._groups_claim = groups_claim
        self._required_scope = required_scope or None

    def authenticate(self, token: str) -> Principal:
        if len(token.encode("utf-8", errors="ignore")) > _MAX_TOKEN_BYTES:
            raise AuthError("token too large")
        # Checked here rather than left to the caller: `split` on a four-segment
        # value raises ValueError, which is not an AuthError and would surface as
        # a 500 instead of a 401 for anyone calling this directly.
        if not looks_like_jws(token):
            raise AuthError("token is not a JWS")
        header_seg, payload_seg, signature_seg = token.split(".")
        header = _json_object(_b64url(header_seg), "header")

        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in _ALGORITHMS:
            # Named before any key lookup, so `none` and HS* never reach one.
            raise AuthError("unsupported token algorithm")
        kid = header.get("kid")
        if kid is not None and not isinstance(kid, str):
            raise AuthError("malformed token header")
        key = self._jwks.get(kid)
        if key is None:
            raise AuthError("unknown token key")

        _verify_signature(alg, key, f"{header_seg}.{payload_seg}".encode("ascii"), _b64url(signature_seg))

        claims = _json_object(_b64url(payload_seg), "payload")
        self._check_claims(claims)

        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject.strip():
            raise AuthError("token has no subject")
        subject = subject.strip()

        grant = self._grants.resolve(subject, self._groups_of(claims))
        if grant is None:
            raise AuthError("no project grant for this subject")

        email = claims.get("email")
        return Principal(
            actor=subject,
            project=grant.project,
            roles=grant.roles,
            # The IDENTITY, not the token instance: an access token is refreshed
            # every few minutes, and binding a pending confirmation to the token
            # string would expire the confirmation whenever the client refreshed.
            token_id=hashlib.sha256(f"{self._issuer}|{subject}".encode("utf-8")).hexdigest()[:12],
            issue_project=grant.issue_project,
            email=email.strip() if isinstance(email, str) and email.strip() else None,
        )

    def _check_claims(self, claims: dict[str, Any]) -> None:
        if claims.get("iss") != self._issuer:
            raise AuthError("token issuer is not accepted")

        aud = claims.get("aud")
        audiences = aud if isinstance(aud, list) else [aud]
        if self._audience not in [a for a in audiences if isinstance(a, str)]:
            raise AuthError("token audience is not accepted")

        now = time.time()
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)) or isinstance(exp, bool):
            raise AuthError("token has no expiry")  # a token that never expires is not one
        if now > float(exp) + self._skew:
            raise AuthError("token has expired")
        for name, message in (("nbf", "token is not valid yet"), ("iat", "token is issued in the future")):
            value = claims.get(name)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                if float(value) > now + self._skew:
                    raise AuthError(message)

        if self._required_scope and self._required_scope not in self._scopes(claims):
            raise AuthError("token lacks the required scope")

    @staticmethod
    def _scopes(claims: dict[str, Any]) -> set[str]:
        scope = claims.get("scope")
        if isinstance(scope, str):
            return set(scope.split())
        scp = claims.get("scp")
        if isinstance(scp, list):
            return {s for s in scp if isinstance(s, str)}
        return set()

    def _groups_of(self, claims: dict[str, Any]) -> tuple[str, ...]:
        raw = claims.get(self._groups_claim)
        if isinstance(raw, str):
            return (raw,)
        if isinstance(raw, list):
            return tuple(g for g in raw if isinstance(g, str) and g)
        return ()


class CompositeAuthenticator:
    """The token file first, then OIDC.

    Order matters and is not an optimization. Resolving the opaque store first
    means an operator-issued token keeps working even if it happens to be
    JWS-shaped, and it means a JWT can never shadow an entry in the file. The OIDC
    path is reached only by a bearer the file does not know.
    """

    def __init__(self, tokens: Any, oidc: OidcAuthenticator | None) -> None:
        self._tokens = tokens
        self._oidc = oidc

    def authenticate_header(self, authorization: str | None) -> Principal:
        try:
            return self._tokens.authenticate_header(authorization)
        except AuthError:
            if self._oidc is None:
                raise
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not token or not looks_like_jws(token):
            raise AuthError("invalid token")
        return self._oidc.authenticate(token)


def discover_jwks_url(issuer: str, opener: Callable[[str], bytes] | None = None) -> str:
    """The `jwks_uri` from the issuer's discovery document.

    The returned URL must be same-origin with the issuer: a discovery document is
    fetched from the issuer but is still a remote answer, and an issuer that could
    be induced to point elsewhere would move the whole trust root.
    """
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    fetch = opener or (lambda u: request.urlopen(
        request.Request(u, headers={"Accept": "application/json"}, method="GET"),
        timeout=_JWKS_TIMEOUT_SEC).read(_MAX_JWKS_BYTES))
    try:
        document = _json_object(fetch(url), "discovery document")
    except (OSError, error.URLError, AuthError, ValueError) as exc:
        raise ValueError(f"OIDC discovery failed for {issuer}: {exc}") from exc
    jwks_uri = document.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri:
        raise ValueError(f"OIDC discovery document for {issuer} has no jwks_uri")
    from urllib.parse import urlsplit

    want, got = urlsplit(issuer), urlsplit(jwks_uri)
    if (got.scheme, got.netloc) != (want.scheme, want.netloc):
        raise ValueError("OIDC discovery returned a jwks_uri on another origin")
    return jwks_uri
