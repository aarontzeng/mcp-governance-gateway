"""OIDC bearer verification.

Everything here signs its own tokens with keys generated in-process, so the
tests exercise the real signature path rather than a stubbed verifier: a test
that patches out the verification proves the plumbing and nothing that matters.
The JWKS is served from an in-memory opener for the same reason — no network,
but the same parsing and caching code.
"""
from __future__ import annotations

import base64
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils as asym_utils

from mcp_governance_gateway.auth import AuthError, BearerTokenAuthenticator, Principal
from mcp_governance_gateway.oidc import (
    CompositeAuthenticator,
    GrantsFile,
    JwksCache,
    OidcAuthenticator,
    discover_jwks_url,
    looks_like_jws,
)

ISSUER = "https://idp.example"
AUDIENCE = "mcp-governance-gateway"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _int_bytes(value: int, length: int | None = None) -> bytes:
    return value.to_bytes(length or (value.bit_length() + 7) // 8, "big")


class _Idp:
    """A key pair plus the JWKS that publishes it, and a token minter."""

    def __init__(self) -> None:
        self.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec = ec.generate_private_key(ec.SECP256R1())
        rn = self.rsa.public_key().public_numbers()
        en = self.ec.public_key().public_numbers()
        self.jwks = {
            "keys": [
                {"kty": "RSA", "kid": "r1", "use": "sig", "n": _b64(_int_bytes(rn.n)), "e": _b64(_int_bytes(rn.e))},
                {"kty": "EC", "kid": "e1", "crv": "P-256",
                 "x": _b64(_int_bytes(en.x, 32)), "y": _b64(_int_bytes(en.y, 32))},
            ]
        }
        self.fetches = 0

    def opener(self, _url: str) -> bytes:
        self.fetches += 1
        return json.dumps(self.jwks).encode()

    def claims(self, **overrides):
        now = int(time.time())
        base = {"iss": ISSUER, "aud": AUDIENCE, "sub": "user-1", "exp": now + 300, "iat": now}
        base.update(overrides)
        return {k: v for k, v in base.items() if v is not None}

    def token(self, claims=None, alg="RS256", kid="r1", signature: bytes | None = None, header=None):
        head = {"alg": alg, "kid": kid, "typ": "JWT"}
        if header:
            head.update(header)
        h = _b64(json.dumps(head).encode())
        p = _b64(json.dumps(claims if claims is not None else self.claims()).encode())
        if signature is None:
            signing_input = f"{h}.{p}".encode()
            if alg.startswith("RS"):
                digest = {"RS256": hashes.SHA256(), "RS384": hashes.SHA384(), "RS512": hashes.SHA512()}[alg]
                signature = self.rsa.sign(signing_input, padding.PKCS1v15(), digest)
            else:
                der = self.ec.sign(signing_input, ec.ECDSA(hashes.SHA256()))
                r, s = asym_utils.decode_dss_signature(der)
                signature = _int_bytes(r, 32) + _int_bytes(s, 32)
        return f"{h}.{p}.{_b64(signature)}"

    def public_pem(self) -> bytes:
        return self.rsa.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )


def _grants_file(payload) -> str:
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(payload, handle)
    handle.close()
    return handle.name


DEFAULT_GRANTS = {
    "subjects": {"user-1": {"project": "team-a", "issue_project": "demo", "roles": ["issue_writer"]}},
    "groups": {"eng": {"project": "team-b", "roles": ["issue_writer"]},
               "ops": {"project": "team-b", "roles": ["ci_runner"]},
               "other": {"project": "team-c"}},
}


class _OidcTestCase(unittest.TestCase):
    grants_payload = DEFAULT_GRANTS

    def setUp(self):
        self.idp = _Idp()
        self.grants_path = _grants_file(self.grants_payload)
        self.addCleanup(lambda: os.path.exists(self.grants_path) and os.unlink(self.grants_path))
        self.cache = JwksCache(f"{ISSUER}/jwks", opener=self.idp.opener)
        self.auth = OidcAuthenticator(ISSUER, AUDIENCE, self.cache, GrantsFile(self.grants_path))


class VerificationTests(_OidcTestCase):
    def test_a_valid_rsa_token_becomes_a_principal(self):
        principal = self.auth.authenticate(self.idp.token())
        self.assertEqual(principal.actor, "user-1")
        self.assertEqual(principal.project, "team-a")
        self.assertEqual(principal.issue_project, "demo")
        self.assertEqual(principal.roles, ("issue_writer",))

    def test_an_ec_token_verifies_too(self):
        # JWS carries ECDSA as raw R||S; `cryptography` verifies DER. A backend that
        # forgets the conversion rejects every EC token, which reads as an IdP fault.
        principal = self.auth.authenticate(self.idp.token(alg="ES256", kid="e1"))
        self.assertEqual(principal.actor, "user-1")

    def test_the_subject_is_the_actor_and_the_email_is_only_a_label(self):
        principal = self.auth.authenticate(self.idp.token(self.idp.claims(email="Someone@Example.com")))
        self.assertEqual(principal.actor, "user-1")   # ADR-0007: the immutable id
        self.assertEqual(principal.email, "Someone@Example.com")

    def test_the_token_id_is_the_identity_not_the_token_string(self):
        # An access token is refreshed every few minutes. Binding a pending
        # confirmation to the token string would expire the confirmation whenever
        # the client refreshed, which is not what the confirmation is protecting.
        first = self.auth.authenticate(self.idp.token(self.idp.claims(exp=int(time.time()) + 100)))
        second = self.auth.authenticate(self.idp.token(self.idp.claims(exp=int(time.time()) + 999)))
        self.assertEqual(first.token_id, second.token_id)
        self.assertNotEqual(first.token_id, "")

    def test_a_tampered_payload_is_refused(self):
        head = _b64(json.dumps({"alg": "RS256", "kid": "r1"}).encode())
        good = _b64(json.dumps(self.idp.claims()).encode())
        signature = self.idp.rsa.sign(f"{head}.{good}".encode(), padding.PKCS1v15(), hashes.SHA256())
        forged = _b64(json.dumps(self.idp.claims(sub="somebody-else")).encode())
        with self.assertRaises(AuthError):
            self.auth.authenticate(f"{head}.{forged}.{_b64(signature)}")

    def test_the_header_algorithm_cannot_choose_the_verification(self):
        # An RS512 header over an RS256 signature must not verify: the digest comes
        # from the named algorithm, so a mismatch has to fail rather than fall back.
        with self.assertRaises(AuthError):
            self.auth.authenticate(self.idp.token(alg="RS512", signature=self.idp.rsa.sign(
                b"anything", padding.PKCS1v15(), hashes.SHA256())))


class RefusedAlgorithmTests(_OidcTestCase):
    """The two refusals that are the whole reason `alg` is not read as an instruction."""

    def test_alg_none_is_refused_before_any_key_lookup(self):
        # RFC 7515's `none` is spelled with an EMPTY signature segment, so the real
        # wire form never reaches the algorithm table -- it fails the JWS shape
        # first. Both spellings are checked: the empty one, and the one that
        # carries a bogus signature so it does reach the allow-list.
        with self.assertRaises(AuthError):
            self.auth.authenticate(self.idp.token(alg="none", signature=b""))

        self.idp.fetches = 0
        with self.assertRaises(AuthError) as caught:
            self.auth.authenticate(self.idp.token(alg="none", signature=b"bogus"))
        self.assertIn("algorithm", str(caught.exception))
        self.assertEqual(self.idp.fetches, 0)  # refused by name; no key was fetched

    def test_an_hmac_token_signed_with_the_published_public_key_is_refused(self):
        # The classic JWT bypass: the JWKS publishes the public key, so if HS256
        # were accepted anyone who can read the JWKS can mint a valid token.
        import hashlib
        import hmac as hmac_mod

        head = _b64(json.dumps({"alg": "HS256", "kid": "r1"}).encode())
        payload = _b64(json.dumps(self.idp.claims(sub="user-1")).encode())
        mac = hmac_mod.new(self.idp.public_pem(), f"{head}.{payload}".encode(), hashlib.sha256).digest()
        with self.assertRaises(AuthError):
            self.auth.authenticate(f"{head}.{payload}.{_b64(mac)}")


class ClaimTests(_OidcTestCase):
    def test_a_token_for_another_audience_is_refused(self):
        with self.assertRaises(AuthError):
            self.auth.authenticate(self.idp.token(self.idp.claims(aud="some-other-client")))

    def test_an_audience_list_containing_ours_is_accepted(self):
        principal = self.auth.authenticate(self.idp.token(self.idp.claims(aud=["account", AUDIENCE])))
        self.assertEqual(principal.actor, "user-1")

    def test_another_issuer_is_refused_even_with_a_valid_signature(self):
        with self.assertRaises(AuthError):
            self.auth.authenticate(self.idp.token(self.idp.claims(iss="https://idp.example.evil")))

    def test_an_expired_token_is_refused(self):
        with self.assertRaises(AuthError):
            self.auth.authenticate(self.idp.token(self.idp.claims(exp=int(time.time()) - 3600)))

    def test_an_infinite_expiry_is_refused_rather_than_never_expiring(self):
        # `json.loads("1e999")` is float('inf'), and `now > inf` is False -- so
        # without a finiteness check this reads as a token that has not expired
        # yet and never will. Same class as `NaN` reaching an int().
        for value in (json.loads("1e999"), json.loads("-1e999"), json.loads("NaN")):
            with self.assertRaises(AuthError, msg=repr(value)):
                self.auth.authenticate(self.idp.token(self.idp.claims(exp=value)))

    def test_an_infinite_nbf_or_iat_cannot_hold_a_token_open_either(self):
        infinite = json.loads("-1e999")
        principal = self.auth.authenticate(self.idp.token(self.idp.claims(nbf=infinite, iat=infinite)))
        self.assertEqual(principal.actor, "user-1")   # ignored, not honoured as "always valid"

    def test_a_token_with_no_expiry_is_refused(self):
        claims = self.idp.claims()
        claims.pop("exp")
        with self.assertRaises(AuthError):
            self.auth.authenticate(self.idp.token(claims))

    def test_a_token_from_the_future_is_refused(self):
        with self.assertRaises(AuthError):
            self.auth.authenticate(self.idp.token(self.idp.claims(nbf=int(time.time()) + 3600)))

    def test_clock_skew_is_applied_to_expiry(self):
        # Expired by 90s: inside a 120s skew, outside the default 60s one.
        just_expired = self.idp.token(self.idp.claims(exp=int(time.time()) - 90))
        lenient = OidcAuthenticator(ISSUER, AUDIENCE, self.cache, GrantsFile(self.grants_path), clock_skew_sec=120)
        self.assertEqual(lenient.authenticate(just_expired).actor, "user-1")
        with self.assertRaises(AuthError):
            self.auth.authenticate(just_expired)

    def test_a_required_scope_is_enforced_when_configured(self):
        strict = OidcAuthenticator(ISSUER, AUDIENCE, self.cache, GrantsFile(self.grants_path),
                                   required_scope="mcpgw")
        with self.assertRaises(AuthError):
            strict.authenticate(self.idp.token(self.idp.claims(scope="openid profile")))
        self.assertEqual(strict.authenticate(self.idp.token(self.idp.claims(scope="openid mcpgw"))).actor, "user-1")

    def test_a_token_without_a_subject_is_refused(self):
        for empty in ("", "   ", None, 42):
            with self.assertRaises(AuthError):
                self.auth.authenticate(self.idp.token({**self.idp.claims(), "sub": empty}))


class GrantTests(_OidcTestCase):
    def test_a_subject_with_no_grant_is_refused_rather_than_given_no_project(self):
        # Policy.decide would deny a project-less principal anyway; refusing here
        # means the audit says "no grant" instead of "missing project".
        with self.assertRaises(AuthError):
            self.auth.authenticate(self.idp.token(self.idp.claims(sub="stranger")))

    def test_a_group_grant_applies_when_the_subject_has_none(self):
        principal = self.auth.authenticate(self.idp.token(self.idp.claims(sub="s2", groups=["eng"])))
        self.assertEqual(principal.project, "team-b")

    def test_two_groups_on_the_same_project_union_their_roles(self):
        principal = self.auth.authenticate(self.idp.token(self.idp.claims(sub="s3", groups=["eng", "ops"])))
        self.assertEqual(principal.project, "team-b")
        self.assertEqual(principal.roles, ("ci_runner", "issue_writer"))

    def test_two_groups_on_different_projects_are_refused_not_resolved(self):
        # Picking one would make a tenant boundary depend on iteration order.
        with self.assertRaises(AuthError):
            self.auth.authenticate(self.idp.token(self.idp.claims(sub="s4", groups=["eng", "other"])))

    def test_a_subject_grant_wins_over_a_group_grant(self):
        principal = self.auth.authenticate(self.idp.token(self.idp.claims(groups=["eng"])))
        self.assertEqual(principal.project, "team-a")

    def test_the_token_cannot_name_its_own_project(self):
        # The IdP knows who someone is, not which tenant of THIS gateway they may
        # act in. A project claim in the token is ignored, not honoured.
        principal = self.auth.authenticate(self.idp.token(self.idp.claims(project="team-z", roles=["issue_writer"])))
        self.assertEqual(principal.project, "team-a")

    def test_a_grant_added_to_the_file_takes_effect_without_a_restart(self):
        grants = GrantsFile(self.grants_path)
        auth = OidcAuthenticator(ISSUER, AUDIENCE, self.cache, grants)
        with self.assertRaises(AuthError):
            auth.authenticate(self.idp.token(self.idp.claims(sub="late")))
        time.sleep(0.01)
        Path(self.grants_path).write_text(json.dumps(
            {"subjects": {"late": {"project": "team-late"}}}), encoding="utf-8")
        self.assertEqual(auth.authenticate(self.idp.token(self.idp.claims(sub="late"))).project, "team-late")

    def test_a_corrupt_grants_file_keeps_the_last_good_mapping_and_says_it_is_stale(self):
        # Last-good on an ALLOW-list is fail-OPEN: the revoked row is still live.
        # Keeping it is still right (a typo must not lock everyone out) but it has
        # to be visible somewhere other than stderr -- /healthz reads this flag.
        grants = GrantsFile(self.grants_path)
        auth = OidcAuthenticator(ISSUER, AUDIENCE, self.cache, grants)
        self.assertEqual(auth.authenticate(self.idp.token()).project, "team-a")
        self.assertFalse(grants.stale)
        time.sleep(0.01)
        Path(self.grants_path).write_text("{ not json", encoding="utf-8")
        self.assertEqual(auth.authenticate(self.idp.token()).project, "team-a")
        self.assertTrue(grants.stale)

    def test_a_repaired_grants_file_is_picked_up_without_waiting_for_another_edit(self):
        # A failed parse must NOT be recorded as the version seen, or a botched
        # offboarding edit stays fail-open until someone touches the file AGAIN.
        #
        # The repair below is written with the SAME byte length and then stamped
        # with the SAME mtime as the corrupt version, and `write_text` truncates
        # in place so the inode is unchanged too -- so (mtime, size, inode) is
        # identical and the ONLY thing that can pick the repair up is the retry.
        # A repair with a different signature would pass whether or not the
        # failed parse was recorded, which is what an earlier version of this
        # test did and why it could not fail.
        good = json.dumps({"subjects": {"user-1": {"project": "repaired"}}})
        corrupt = "{" * len(good)
        self.assertEqual(len(corrupt), len(good))

        path = Path(self.grants_path)
        grants = GrantsFile(self.grants_path)
        auth = OidcAuthenticator(ISSUER, AUDIENCE, self.cache, grants)
        time.sleep(0.01)
        path.write_text(corrupt, encoding="utf-8")
        stamp = path.stat()
        self.assertEqual(auth.authenticate(self.idp.token()).project, "team-a")
        self.assertTrue(grants.stale)

        inode_before = stamp.st_ino
        path.write_text(good, encoding="utf-8")
        os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        after = path.stat()
        self.assertEqual((after.st_mtime_ns, after.st_size, after.st_ino),
                         (stamp.st_mtime_ns, stamp.st_size, inode_before),
                         "the fixture failed to reproduce an identical signature")

        self.assertEqual(auth.authenticate(self.idp.token()).project, "repaired")
        self.assertFalse(grants.stale)

    def test_a_grants_file_that_is_absent_at_startup_is_a_boot_failure(self):
        with self.assertRaises(Exception):
            GrantsFile("/nonexistent/grants.json")


class JwksTests(_OidcTestCase):
    def test_the_key_set_is_cached_rather_than_fetched_per_request(self):
        self.idp.fetches = 0
        cache = JwksCache(f"{ISSUER}/jwks", opener=self.idp.opener)
        auth = OidcAuthenticator(ISSUER, AUDIENCE, cache, GrantsFile(self.grants_path))
        for _ in range(5):
            auth.authenticate(self.idp.token())
        self.assertEqual(self.idp.fetches, 1)

    def test_an_unknown_kid_is_refused_and_does_not_stampede_the_idp(self):
        cache = JwksCache(f"{ISSUER}/jwks", opener=self.idp.opener)
        cache.get("r1")
        self.idp.fetches = 0
        for _ in range(5):
            self.assertIsNone(cache.get("rotated-kid"))
        self.assertLessEqual(self.idp.fetches, 1)  # one refetch attempt, then the cooldown

    def test_an_unreachable_idp_keeps_the_last_good_keys(self):
        cache = JwksCache(f"{ISSUER}/jwks", ttl_sec=0, refetch_cooldown_sec=0, opener=self.idp.opener)
        auth = OidcAuthenticator(ISSUER, AUDIENCE, cache, GrantsFile(self.grants_path))
        self.assertEqual(auth.authenticate(self.idp.token()).actor, "user-1")

        def broken(_url):
            raise OSError("idp is down")

        cache._open = broken
        self.assertEqual(auth.authenticate(self.idp.token()).actor, "user-1")

    def test_a_key_set_with_no_usable_key_does_not_replace_a_good_one(self):
        cache = JwksCache(f"{ISSUER}/jwks", ttl_sec=0, refetch_cooldown_sec=0, opener=self.idp.opener)
        self.assertIsNotNone(cache.get("r1"))
        cache._open = lambda _u: json.dumps({"keys": [{"kty": "OKP", "kid": "x"}]}).encode()
        self.assertIsNotNone(cache.get("r1"))

    def test_an_encryption_key_is_not_used_as_a_signing_key(self):
        jwks = json.loads(json.dumps(self.idp.jwks))
        jwks["keys"][0]["use"] = "enc"
        cache = JwksCache(f"{ISSUER}/jwks", opener=lambda _u: json.dumps(jwks).encode())
        self.assertIsNone(cache.get("r1"))

    def test_a_slow_idp_does_not_block_every_other_authentication(self):
        # The refresh must not hold the lock across the network call: one slow IdP
        # would otherwise serialize every OIDC authentication in the process, which
        # an attacker can trigger on demand with a rotating unknown kid.
        import threading as _t
        released = _t.Event()
        payload = json.dumps(self.idp.jwks).encode()

        def slow(_url):
            released.wait(2.0)
            return payload

        cache = JwksCache(f"{ISSUER}/jwks", opener=slow)
        cache._keys = {"r1": "placeholder"}          # a last-good set to serve meanwhile
        cache._fetched_at = 0.0                      # ... which is stale, so a fetch starts
        fetcher = _t.Thread(target=cache.get, args=("r1",), daemon=True)
        fetcher.start()
        time.sleep(0.05)                             # let it get into the fetch

        answered = _t.Event()
        _t.Thread(target=lambda: (cache.get("r1"), answered.set()), daemon=True).start()
        self.assertTrue(answered.wait(1.0), "a second caller blocked on the in-flight fetch")
        released.set()
        fetcher.join(timeout=3)

    def test_a_missing_kid_resolves_only_when_the_issuer_publishes_one_key(self):
        many = JwksCache(f"{ISSUER}/jwks", opener=self.idp.opener)
        self.assertIsNone(many.get(None))
        single = json.dumps({"keys": [self.idp.jwks["keys"][0]]}).encode()
        one = JwksCache(f"{ISSUER}/jwks", opener=lambda _u: single)
        self.assertIsNotNone(one.get(None))


class DiscoveryTests(unittest.TestCase):
    def test_the_jwks_uri_comes_from_the_discovery_document(self):
        document = json.dumps({"jwks_uri": f"{ISSUER}/protocol/openid-connect/certs"}).encode()
        self.assertEqual(discover_jwks_url(ISSUER, opener=lambda _u: document),
                         f"{ISSUER}/protocol/openid-connect/certs")

    def test_a_jwks_uri_on_another_origin_is_refused(self):
        # The discovery document is a remote answer. An issuer that can be induced
        # to point elsewhere would move the entire trust root.
        document = json.dumps({"jwks_uri": "https://attacker.example/certs"}).encode()
        with self.assertRaises(ValueError):
            discover_jwks_url(ISSUER, opener=lambda _u: document)

    def test_a_document_without_a_jwks_uri_is_a_boot_failure(self):
        with self.assertRaises(ValueError):
            discover_jwks_url(ISSUER, opener=lambda _u: b"{}")


class MalformedTokenTests(_OidcTestCase):
    def test_garbage_in_the_bearer_position_raises_autherror_not_a_crash(self):
        # Every one of these must be an AuthError -> 401. A ValueError escaping
        # here is a 500, which tells an attacker their input reached the parser.
        junk = [
            "", ".", "...", "a.b", "a.b.c.d", "a..c", ".b.c", "a.b.",
            "!!!.@@@.###",                                   # not base64url at all
            _b64(b"[]") + "." + _b64(b"{}") + ".AA",         # header is a JSON array
            _b64(b"{}") + "." + _b64(b"nope") + ".AA",       # payload is not JSON
            _b64(b'{"alg":"RS256"}') + "." + _b64(b"{}") + ".AA",
        ]
        for value in junk:
            with self.assertRaises(AuthError, msg=f"accepted or crashed on {value!r}"):
                self.auth.authenticate(value)

    def test_an_oversized_token_is_refused_without_parsing(self):
        with self.assertRaises(AuthError):
            self.auth.authenticate("a." + "x" * 20_000 + ".c")

    def test_a_non_ascii_segment_is_an_autherror_not_a_unicode_crash(self):
        # The signing input is built with .encode("ascii"), which raises
        # UnicodeEncodeError on a non-ASCII segment -- not an AuthError, so a 500
        # instead of a 401, which tells a caller their input reached the parser.
        # http.server decodes headers as latin-1, so this is reachable from the wire.
        head = _b64(json.dumps({"alg": "RS256", "kid": "r1"}).encode())
        for token in (f"{head}.é.AA", f"é.{head}.AA", f"{head}.AA.é", "ü.ü.ü"):
            with self.assertRaises(AuthError, msg=token):
                self.auth.authenticate(token)

    def test_an_ecdsa_signature_of_zeroes_is_refused_on_any_cryptography_version(self):
        # r or s of zero is not a valid ECDSA signature. Older `cryptography`
        # encodes (0, 0) happily and lets verify fail; newer versions raise
        # ValueError from encode_dss_signature, which is not an AuthError.
        head = _b64(json.dumps({"alg": "ES256", "kid": "e1"}).encode())
        payload = _b64(json.dumps(self.idp.claims()).encode())
        for signature in (bytes(64), bytes(32) + b"\x01" * 32, b"\x01" * 32 + bytes(32)):
            with self.assertRaises(AuthError):
                self.auth.authenticate(f"{head}.{payload}.{_b64(signature)}")

    def test_the_padded_spelling_of_a_segment_is_not_accepted(self):
        # base64url in a JWS is unpadded. A decoder that accepts several spellings
        # is a decoder two implementations can disagree about.
        token = self.idp.token()
        head, payload, signature = token.split(".")
        with self.assertRaises(AuthError):
            self.auth.authenticate(f"{head}=.{payload}.{signature}")


class EmptyStoreBootTests(unittest.TestCase):
    """An OIDC deployment that also names a runtime token store must boot.

    The empty-merge guard catches a misconfigured token file, which is the right
    default. It is wrong when identities come from an IdP and the runtime store
    is simply still empty -- the normal state before the first token is minted.
    """

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = Path(self.dir.name) / "user-tokens.json"
        self.path.write_text(json.dumps({"tokens": []}), encoding="utf-8")

    def test_an_empty_optional_store_still_refuses_to_boot_by_default(self):
        with self.assertRaises(ValueError):
            BearerTokenAuthenticator.from_files([(self.path, False)])

    def test_an_empty_optional_store_is_allowed_when_identities_come_from_elsewhere(self):
        auth = BearerTokenAuthenticator.from_files([(self.path, False)], allow_empty=True)
        with self.assertRaises(AuthError):
            auth.authenticate_header("Bearer anything")   # empty, so it refuses everyone

    def test_a_token_minted_into_it_later_takes_effect_without_a_restart(self):
        auth = BearerTokenAuthenticator.from_files([(self.path, False)], allow_empty=True)
        time.sleep(0.01)
        self.path.write_text(json.dumps(
            {"tokens": [{"token": "t", "actor": "1", "project": "p", "roles": []}]}), encoding="utf-8")
        self.assertEqual(auth.authenticate_header("Bearer t").actor, "1")


class CompositeTests(_OidcTestCase):
    def setUp(self):
        super().setUp()
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump({"tokens": [{"token": "opaque-1", "actor": "9", "project": "legacy", "roles": []}]}, handle)
        handle.close()
        self.token_path = handle.name
        self.addCleanup(lambda: os.unlink(self.token_path))
        self.tokens = BearerTokenAuthenticator.from_file(self.token_path)

    def test_an_opaque_token_still_resolves_when_oidc_is_configured(self):
        composite = CompositeAuthenticator(self.tokens, self.auth)
        self.assertEqual(composite.authenticate_header("Bearer opaque-1").project, "legacy")

    def test_a_jwt_resolves_through_the_oidc_path(self):
        composite = CompositeAuthenticator(self.tokens, self.auth)
        self.assertEqual(composite.authenticate_header(f"Bearer {self.idp.token()}").project, "team-a")

    def test_the_token_file_is_consulted_first_so_a_jwt_cannot_shadow_an_entry(self):
        jws_shaped = self.idp.token()
        Path(self.token_path).write_text(json.dumps(
            {"tokens": [{"token": jws_shaped, "actor": "9", "project": "operator-issued", "roles": []}]}),
            encoding="utf-8")
        composite = CompositeAuthenticator(BearerTokenAuthenticator.from_file(self.token_path), self.auth)
        self.assertEqual(composite.authenticate_header(f"Bearer {jws_shaped}").project, "operator-issued")

    def test_without_oidc_the_behaviour_is_exactly_the_token_file(self):
        composite = CompositeAuthenticator(self.tokens, None)
        self.assertEqual(composite.authenticate_header("Bearer opaque-1").actor, "9")
        with self.assertRaises(AuthError):
            composite.authenticate_header(f"Bearer {self.idp.token()}")

    def test_an_unknown_bearer_is_refused_by_both(self):
        composite = CompositeAuthenticator(self.tokens, self.auth)
        for header in (None, "", "Basic x", "Bearer ", "Bearer nope"):
            with self.assertRaises(AuthError):
                composite.authenticate_header(header)


class ShippedExampleTests(unittest.TestCase):
    def test_the_shipped_grants_example_parses_and_resolves(self):
        # An example an adopter copies must actually load. The `_comment` key it
        # carries is ignored rather than rejected -- JSON has no comments and a
        # config file people read deserves prose in it.
        path = Path(__file__).resolve().parent.parent / "config" / "examples" / "oidc-grants.example.json"
        grants = GrantsFile(path)
        subject = json.loads(path.read_text(encoding="utf-8"))
        sub_id = next(iter(subject["subjects"]))
        self.assertEqual(grants.resolve(sub_id, ()).project, "demo-project")
        self.assertEqual(grants.resolve("nobody", ("mcp-demo-writers",)).roles, ("issue_writer",))
        self.assertIsNone(grants.resolve("nobody", ()))


class ShapeTests(unittest.TestCase):
    def test_looks_like_jws_is_shape_only(self):
        self.assertTrue(looks_like_jws("a.b.c"))
        for not_jws in ("a.b", "a.b.c.d", ".b.c", "a..c", "a.b.", "plain-token"):
            self.assertFalse(looks_like_jws(not_jws))


if __name__ == "__main__":
    unittest.main()
