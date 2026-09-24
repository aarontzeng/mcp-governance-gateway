"""Bearer tokens: the token file and its hot reload, signed identity propagation, and the issue_project claim's compatibility name."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from mcp_governance_gateway.auth import (
    AuthError,
    BearerTokenAuthenticator,
    IdentityVerifier,
    Principal,
)
from mcp_governance_gateway.server import _is_loopback_host, is_origin_allowed


class TokenFileTests(unittest.TestCase):
    def test_loads_token_file_without_logging_raw_token(self) -> None:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as token_file:
            json.dump(
                {
                    "tokens": [
                        {
                            "token": "pilot-token",
                            "actor": "user@example.com",
                            "project": "example-project",
                            "roles": ["developer"],
                        }
                    ]
                },
                token_file,
            )
            token_file.flush()
            authenticator = BearerTokenAuthenticator.from_file(token_file.name)

        principal = authenticator.authenticate_header("Bearer pilot-token")
        self.assertEqual(principal.actor, "user@example.com")
        self.assertNotEqual(principal.token_id, "pilot-token")

    def test_authenticator_rejects_missing_or_invalid_token(self) -> None:
        authenticator = BearerTokenAuthenticator(
            {
                "pilot-token": Principal(
                    actor="user@example.com",
                    project="example-project",
                    roles=("developer",),
                    token_id="tok_1",
                )
            }
        )

        with self.assertRaises(AuthError):
            authenticator.authenticate_header(None)
        with self.assertRaises(AuthError):
            authenticator.authenticate_header("Bearer wrong-token")

    def test_origin_validation_rejects_untrusted_browser_origins(self) -> None:
        allowed = ("https://agent.example.internal",)

        self.assertTrue(is_origin_allowed(None, allowed))
        self.assertTrue(is_origin_allowed("https://agent.example.internal", allowed))
        self.assertFalse(is_origin_allowed("https://evil.example", allowed))

    def test_is_loopback_host_classifies_bind_addresses(self) -> None:
        for host in ("127.0.0.1", "::1", "localhost"):
            self.assertTrue(_is_loopback_host(host))
        for host in ("0.0.0.0", "10.0.0.5", "192.168.1.9", "203.0.113.7", "gateway.internal"):
            self.assertFalse(_is_loopback_host(host))


class IdentityVerifierTests(unittest.TestCase):
    PREFIX = "X-Forwarded-User"
    SECRET = "shared-identity-secret"

    def setUp(self) -> None:
        self.base = Principal(
            actor="service-account",
            project="example-project",
            roles=("developer", "issue_writer"),
            token_id="tok_1",
            issue_project="97",
        )

    @staticmethod
    def _get(headers: dict[str, str]):
        return headers.get

    def _sign(self, user_id: str, email: str) -> str:
        import hashlib
        import hmac

        return hmac.new(self.SECRET.encode(), f"{user_id}:{email}".encode(), hashlib.sha256).hexdigest()

    def test_disabled_when_no_secret_ignores_identity_headers(self) -> None:
        verifier = IdentityVerifier(secret="", prefix=self.PREFIX)
        headers = {f"{self.PREFIX}-Id": "attacker@evil.example", f"{self.PREFIX}-Claims-Signature": "deadbeef"}
        self.assertEqual(verifier.resolve(self._get(headers), self.base), self.base)

    def test_no_identity_headers_returns_base(self) -> None:
        verifier = IdentityVerifier(secret=self.SECRET, prefix=self.PREFIX)
        self.assertEqual(verifier.resolve(self._get({}), self.base), self.base)

    def test_valid_signature_overrides_only_actor(self) -> None:
        verifier = IdentityVerifier(secret=self.SECRET, prefix=self.PREFIX)
        headers = {
            f"{self.PREFIX}-Id": "alice@example.com",
            f"{self.PREFIX}-Email": "alice@example.com",
            f"{self.PREFIX}-Claims-Signature": self._sign("alice@example.com", "alice@example.com"),
        }
        resolved = verifier.resolve(self._get(headers), self.base)
        self.assertEqual(resolved.actor, "alice@example.com")
        # authorization scope is untouched — only the audit/attribution actor changes
        self.assertEqual(resolved.project, self.base.project)
        self.assertEqual(resolved.roles, self.base.roles)
        self.assertEqual(resolved.redmine_project, self.base.redmine_project)
        self.assertEqual(resolved.token_id, self.base.token_id)

    def test_forged_identity_without_valid_signature_is_rejected(self) -> None:
        verifier = IdentityVerifier(secret=self.SECRET, prefix=self.PREFIX)
        headers = {
            f"{self.PREFIX}-Id": "attacker@evil.example",
            f"{self.PREFIX}-Email": "attacker@evil.example",
            f"{self.PREFIX}-Claims-Signature": "0" * 64,
        }
        with self.assertRaises(AuthError):
            verifier.resolve(self._get(headers), self.base)

    def test_signature_must_match_exact_id_and_email(self) -> None:
        # a valid signature for alice cannot be replayed with a different id
        verifier = IdentityVerifier(secret=self.SECRET, prefix=self.PREFIX)
        headers = {
            f"{self.PREFIX}-Id": "mallory@evil.example",
            f"{self.PREFIX}-Email": "alice@example.com",
            f"{self.PREFIX}-Claims-Signature": self._sign("alice@example.com", "alice@example.com"),
        }
        with self.assertRaises(AuthError):
            verifier.resolve(self._get(headers), self.base)

    def test_identity_id_without_signature_is_rejected(self) -> None:
        verifier = IdentityVerifier(secret=self.SECRET, prefix=self.PREFIX)
        headers = {f"{self.PREFIX}-Id": "alice@example.com"}
        with self.assertRaises(AuthError):
            verifier.resolve(self._get(headers), self.base)


class MultiFileTokenReloadTests(unittest.TestCase):
    @staticmethod
    def _write(path: Path, tokens: list) -> None:
        path.write_text(json.dumps({"tokens": tokens}), encoding="utf-8")

    @staticmethod
    def _bump_mtime(path: Path) -> None:
        import os
        import time
        future = time.time() + 5
        os.utime(path, (future, future))

    def test_merges_base_and_user_token_files(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            base, user = Path(d) / "base.json", Path(d) / "user.json"
            self._write(base, [{"token": "svc", "actor": "gateway-x", "project": "x", "roles": ["developer"]}])
            self._write(user, [{"token": "usr", "actor": "alice@x", "project": "x", "roles": ["developer"], "redmine_project": "160"}])
            auth = BearerTokenAuthenticator.from_files([(base, True), (user, False)])
            self.assertEqual(auth.authenticate_header("Bearer svc").actor, "gateway-x")
            self.assertEqual(auth.authenticate_header("Bearer usr").actor, "alice@x")
            self.assertEqual(auth.authenticate_header("Bearer usr").redmine_project, "160")

    def test_optional_user_file_absent_or_empty_ok(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            base, user = Path(d) / "base.json", Path(d) / "user.json"
            self._write(base, [{"token": "svc", "actor": "gw", "project": "x", "roles": []}])
            auth = BearerTokenAuthenticator.from_files([(base, True), (user, False)])  # user absent
            self.assertEqual(auth.authenticate_header("Bearer svc").project, "x")
            self._write(user, [])  # user empty
            auth2 = BearerTokenAuthenticator.from_files([(base, True), (user, False)])
            self.assertEqual(auth2.authenticate_header("Bearer svc").project, "x")

    def test_required_file_missing_raises(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                BearerTokenAuthenticator.from_files([(Path(d) / "nope.json", True)])

    def test_hot_reload_picks_up_new_user_token(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            base, user = Path(d) / "base.json", Path(d) / "user.json"
            self._write(base, [{"token": "svc", "actor": "gw", "project": "x", "roles": []}])
            self._write(user, [])
            auth = BearerTokenAuthenticator.from_files([(base, True), (user, False)])
            with self.assertRaises(AuthError):
                auth.authenticate_header("Bearer newusr")
            self._write(user, [{"token": "newusr", "actor": "bob@x", "project": "x", "roles": ["developer"]}])
            self._bump_mtime(user)
            self.assertEqual(auth.authenticate_header("Bearer newusr").actor, "bob@x")  # hot-reloaded

    def test_corrupt_user_file_keeps_last_good(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            base, user = Path(d) / "base.json", Path(d) / "user.json"
            self._write(base, [{"token": "svc", "actor": "gw", "project": "x", "roles": []}])
            self._write(user, [{"token": "usr", "actor": "a@x", "project": "x", "roles": []}])
            auth = BearerTokenAuthenticator.from_files([(base, True), (user, False)])
            self.assertEqual(auth.authenticate_header("Bearer usr").actor, "a@x")
            user.write_text("{ not valid json", encoding="utf-8")
            self._bump_mtime(user)
            # corrupt reload keeps last-good map; both tokens still authenticate --
            # and says so on stderr, because a revoke in that file did NOT land.
            with self.assertLogs("mcp_governance_gateway", level="WARNING") as logs:
                self.assertEqual(auth.authenticate_header("Bearer usr").actor, "a@x")
            self.assertEqual(auth.authenticate_header("Bearer svc").project, "x")
            self.assertIn("token file reload failed", "\n".join(logs.output))
            self.assertIn("last-good", "\n".join(logs.output))

    def test_the_shipped_example_token_file_parses(self) -> None:
        # config/examples/tokens.example.json is what .env.example points people at;
        # it must stay loadable by the real parser.
        example = Path(__file__).resolve().parents[1] / "config" / "examples" / "tokens.example.json"
        auth = BearerTokenAuthenticator.from_files([(example, True)])
        principal = auth.authenticate_header("Bearer replace-with-random-pilot-token")
        self.assertEqual(principal.actor, "user@example.com")
        self.assertEqual(principal.project, "example-project")

    def test_hot_reload_drops_revoked_token(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            base, user = Path(d) / "base.json", Path(d) / "user.json"
            self._write(base, [{"token": "svc", "actor": "gw", "project": "x", "roles": []}])
            self._write(user, [{"token": "usr", "actor": "a@x", "project": "x", "roles": []}])
            auth = BearerTokenAuthenticator.from_files([(base, True), (user, False)])
            self.assertEqual(auth.authenticate_header("Bearer usr").actor, "a@x")
            self._write(user, [])  # revoke: remove usr
            self._bump_mtime(user)
            with self.assertRaises(AuthError):
                auth.authenticate_header("Bearer usr")  # revoked token rejected after reload
            self.assertEqual(auth.authenticate_header("Bearer svc").project, "x")

    def test_two_overlapping_reloads_cannot_publish_the_older_file_last(self) -> None:
        # Thread 1 sees the file change and reads version B (usr still valid); before
        # it can publish, version C (usr revoked) lands and thread 2 reads and
        # publishes it. Thread 1 must not then overwrite C with B: a revoked token
        # would authenticate until the next reload. Asserted on the live map, not
        # through authenticate_header, which would repair it by reloading again.
        with tempfile.TemporaryDirectory() as d:
            base, user = Path(d) / "base.json", Path(d) / "user.json"
            self._write(base, [{"token": "svc", "actor": "gw", "project": "x", "roles": []}])
            self._write(user, [])
            auth = BearerTokenAuthenticator.from_files([(base, True), (user, False)])
            self._write(user, [{"token": "usr", "actor": "a@x", "project": "x", "roles": []}])  # version B
            self._bump_mtime(user)
            real_load = BearerTokenAuthenticator._load_all
            first_read_done, second_published = threading.Event(), threading.Event()
            calls = []

            def slow_first_load(sources):
                loaded = real_load(sources)
                calls.append(1)
                if len(calls) == 1:
                    first_read_done.set()
                    second_published.wait(0.5)   # give a racing reload time to publish C
                return loaded

            with mock.patch.object(BearerTokenAuthenticator, "_load_all", staticmethod(slow_first_load)):
                t1 = threading.Thread(target=auth._maybe_reload)
                t1.start()
                self.assertTrue(first_read_done.wait(5))
                self._write(user, [])                          # version C: usr revoked
                os.utime(user, (time.time() + 10, time.time() + 10))
                t2 = threading.Thread(target=auth._maybe_reload)
                t2.start()
                t2.join(5)
                second_published.set()
                t1.join(5)
            self.assertNotIn("usr", auth._token_claims)
            self.assertEqual(auth.authenticate_header("Bearer svc").project, "x")

    def test_reload_recovers_after_corrupt(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            base, user = Path(d) / "base.json", Path(d) / "user.json"
            self._write(base, [{"token": "svc", "actor": "gw", "project": "x", "roles": []}])
            self._write(user, [{"token": "usr", "actor": "a@x", "project": "x", "roles": []}])
            auth = BearerTokenAuthenticator.from_files([(base, True), (user, False)])
            user.write_text("{ broken", encoding="utf-8")
            self._bump_mtime(user)
            self.assertEqual(auth.authenticate_header("Bearer usr").actor, "a@x")  # last-good kept
            self._write(user, [{"token": "usr2", "actor": "b@x", "project": "x", "roles": []}])
            self._bump_mtime(user)
            self.assertEqual(auth.authenticate_header("Bearer usr2").actor, "b@x")  # un-wedges after a corrupt load

    def test_user_file_overrides_base_on_duplicate_token(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            base, user = Path(d) / "base.json", Path(d) / "user.json"
            self._write(base, [{"token": "dup", "actor": "gateway", "project": "x", "roles": []}])
            self._write(user, [{"token": "dup", "actor": "person@x", "project": "x", "roles": []}])
            auth = BearerTokenAuthenticator.from_files([(base, True), (user, False)])
            self.assertEqual(auth.authenticate_header("Bearer dup").actor, "person@x")  # later source wins

    def test_non_ascii_token_raises_autherror_not_typeerror(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            base = Path(d) / "base.json"
            self._write(base, [{"token": "svc", "actor": "gw", "project": "x", "roles": []}])
            auth = BearerTokenAuthenticator.from_files([(base, True)])
            with self.assertRaises(AuthError):
                auth.authenticate_header("Bearer ÿé")  # latin-1 non-ASCII bearer -> 401 not 500


class IssueProjectRenameCompatTests(unittest.TestCase):
    """The token store's field was renamed redmine_project -> issue_project.
    Tokens minted before the rename must keep working without a re-mint."""

    def _principals(self, entries):
        """Drive the public path: a real token file through the authenticator."""
        d = tempfile.mkdtemp()
        p = os.path.join(d, "tokens.json")
        with open(p, "w") as fh:
            json.dump({"tokens": entries}, fh)
        auth = BearerTokenAuthenticator.from_files([(p, True)])
        return {e["token"]: auth.authenticate_header("Bearer " + e["token"]) for e in entries}

    def test_legacy_redmine_project_field_still_read(self):
        claims = self._principals([{"token": "t", "actor": "a", "project": "p",
                                    "roles": ["developer"], "redmine_project": "160"}])
        self.assertEqual(claims["t"].issue_project, "160")
        self.assertEqual(claims["t"].redmine_project, "160")  # deprecated alias

    def test_new_issue_project_field_read(self):
        claims = self._principals([{"token": "t", "actor": "a", "project": "p",
                                    "roles": ["developer"], "issue_project": "158"}])
        self.assertEqual(claims["t"].issue_project, "158")

    def test_new_field_wins_when_both_present(self):
        claims = self._principals([{"token": "t", "actor": "a", "project": "p", "roles": [],
                                    "issue_project": "158", "redmine_project": "160"}])
        self.assertEqual(claims["t"].issue_project, "158")

    def test_absent_in_both_is_none(self):
        claims = self._principals([{"token": "t", "actor": "a", "project": "p", "roles": []}])
        self.assertIsNone(claims["t"].issue_project)
        self.assertIsNone(claims["t"].redmine_project)

    def test_integer_value_is_stringified(self):
        claims = self._principals([{"token": "t", "actor": "a", "project": "p",
                                    "roles": [], "redmine_project": 160}])
        self.assertEqual(claims["t"].issue_project, "160")

    def test_bad_type_rejected_under_new_name(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "tokens.json")
        with open(p, "w") as fh:
            json.dump({"tokens": [{"token": "t", "actor": "a", "project": "p",
                                   "roles": [], "issue_project": ["nope"]}]}, fh)
        with self.assertRaises(ValueError):
            BearerTokenAuthenticator.from_files([(p, True)])
