"""HTTP-level tests for the credential-enrollment routes.

These had none. `InternalApiTests` in test_redmine_keystore.py exercises the
`InternalApi` object directly, so the routing, the 401 path, the Origin check
and the "identity propagation is not applied here" guarantee were all asserted
only by a comment. This drives a real socket against a real handler.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import unittest
import urllib.error
import urllib.request
from http import HTTPStatus

from mcp_governance_gateway.audit import AuditSink
from mcp_governance_gateway.auth import BearerTokenAuthenticator, IdentityVerifier, Principal
from mcp_governance_gateway.internal_api import InternalApi
from mcp_governance_gateway.server import GatewayHTTPServer, make_handler

TOKEN = "opaque-token-1"
OTHER = "opaque-token-2"


class _Audit(AuditSink):
    def __init__(self):
        self.events = []

    def write(self, event):
        self.events.append(event)


class _Keystore:
    """Enough of RedmineKeyStore for the routes; the real one has its own suite."""

    degraded = False

    def __init__(self):
        self.keys: dict[str, str] = {}

    def status(self, actor, backend="redmine"):
        return {"hasKey": actor in self.keys, "state": "ok" if actor in self.keys else "missing",
                "redmineLogin": None, "degraded": False}

    def set(self, actor, plaintext, login, backend="redmine"):
        self.keys[actor] = plaintext

    def clear(self, actor):
        return self.keys.pop(actor, None) is not None

    def get(self, actor, backend="redmine"):
        from mcp_governance_gateway.redmine_keystore import KeyState
        return (KeyState.OK, self.keys[actor]) if actor in self.keys else (KeyState.MISSING, None)


class _Issues:
    def verify_key(self, key):
        return {"login": "alice", "mail": "alice@example.com"} if key == "good-key" else None

    def list_assigned_to_me(self, context):
        return {"issues": []}


class _Server(unittest.TestCase):
    serves_internal = True
    identity_secret = ""

    def setUp(self):
        principals = {
            TOKEN: Principal(actor="1", project="p", roles=(), token_id="t1",
                             issue_project="demo", email="alice@example.com"),
            OTHER: Principal(actor="2", project="p", roles=(), token_id="t2",
                             issue_project="demo", email="bob@example.com"),
        }
        self.audit = _Audit()
        self.keystore = _Keystore()
        self.server = GatewayHTTPServer(("127.0.0.1", 0), make_handler())
        self.server.app = None
        self.server.authenticator = BearerTokenAuthenticator(principals)
        self.server.identity_verifier = IdentityVerifier(secret=self.identity_secret)
        self.server.allowed_origins = ("https://portal.example",)
        self.server.keystore = self.keystore
        self.server.internal_api = InternalApi(self.keystore, _Issues(), self.audit, backend_name="redmine")
        self.server.audit_sink = self.audit
        self.server.serves_internal = self.serves_internal
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def _stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def call(self, path, method="GET", token=TOKEN, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method)
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return exc.code, {"raw": raw.decode("utf-8", "replace")}


class RoutingTests(_Server):
    def test_the_canonical_and_legacy_paths_are_the_same_route(self):
        # The old spelling is what every deployed enrollment page calls.
        for path in ("/internal/credentials", "/internal/redmine-key"):
            status, payload = self.call(path)
            self.assertEqual(status, HTTPStatus.OK, path)
            self.assertIn("hasKey", payload)

    def test_a_trailing_slash_and_a_query_string_reach_the_same_route(self):
        for path in ("/internal/credentials/", "/internal/credentials?x=1"):
            self.assertEqual(self.call(path)[0], HTTPStatus.OK, path)

    def test_my_issues_is_reachable_and_fails_closed_without_a_key(self):
        status, payload = self.call("/internal/my-issues")
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(payload, {"hasKey": False, "issues": []})

    def test_an_unknown_path_under_internal_is_not_routed_here(self):
        # 405 rather than 404 is the handler's pre-existing answer for every
        # unrouted GET, not something this surface chose; asserted so a change
        # to that fall-through shows up as a test rather than as a surprise.
        self.assertEqual(self.call("/internal/whatever")[0], HTTPStatus.METHOD_NOT_ALLOWED)
        self.assertEqual(self.call("/internal/whatever", "POST", body={})[0], HTTPStatus.NOT_FOUND)


class AuthenticationTests(_Server):
    def test_no_bearer_is_unauthorized(self):
        status, payload = self.call("/internal/credentials", token=None)
        self.assertEqual(status, HTTPStatus.UNAUTHORIZED)
        self.assertEqual(payload, {"error": "unauthorized"})

    def test_an_unknown_bearer_is_unauthorized_and_says_nothing_else(self):
        status, payload = self.call("/internal/credentials", token="nope")
        self.assertEqual(status, HTTPStatus.UNAUTHORIZED)
        self.assertEqual(payload, {"error": "unauthorized"})

    def test_the_route_acts_only_on_the_bearer_s_own_actor(self):
        self.assertEqual(self.call("/internal/credentials", "POST", body={"key": "good-key"})[0], HTTPStatus.OK)
        self.assertEqual(set(self.keystore.keys), {"1"})
        status, _ = self.call("/internal/credentials", "POST", token=OTHER, body={"key": "good-key"})
        self.assertEqual(status, HTTPStatus.FORBIDDEN)   # bob's token, alice's downstream account
        self.assertEqual(set(self.keystore.keys), {"1"})


class ForgedIdentityTests(_Server):
    identity_secret = "shared-secret"

    def _signed(self, user_id, email=""):
        mac = hmac.new(self.identity_secret.encode(), f"{user_id}:{email}".encode(), hashlib.sha256)
        return {"X-Forwarded-User-Id": user_id, "X-Forwarded-User-Email": email,
                "X-Forwarded-User-Claims-Signature": mac.hexdigest()}

    def test_a_validly_signed_identity_header_cannot_retarget_the_enrolment(self):
        # On /mcp these headers DO override the actor. Here they must not: the
        # whole point of this surface is that it acts on the bearer's own actor.
        # Asserted only by a comment in server.py until now.
        status, _ = self.call("/internal/credentials", "POST", body={"key": "good-key"},
                              headers=self._signed("99", "alice@example.com"))
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(set(self.keystore.keys), {"1"})   # not "99"


class OriginTests(_Server):
    def test_a_state_changing_call_from_a_foreign_origin_is_refused(self):
        # These are reachable by a browser holding the bearer; /mcp has had this
        # check since 0.1.0 and these routes had not.
        for method, body in (("POST", {"key": "good-key"}), ("DELETE", None)):
            status, payload = self.call("/internal/credentials", method, body=body,
                                        headers={"Origin": "https://evil.example"})
            self.assertEqual(status, HTTPStatus.FORBIDDEN, method)
            self.assertEqual(payload, {"error": "forbidden origin"})
        self.assertEqual(self.keystore.keys, {})

    def test_the_configured_origin_is_allowed(self):
        status, _ = self.call("/internal/credentials", "POST", body={"key": "good-key"},
                              headers={"Origin": "https://portal.example"})
        self.assertEqual(status, HTTPStatus.OK)

    def test_a_read_is_not_origin_checked(self):
        # A GET changes nothing, and refusing it would break a page that reads
        # enrollment status before it writes anything.
        self.assertEqual(self.call("/internal/credentials",
                                   headers={"Origin": "https://evil.example"})[0], HTTPStatus.OK)


class AdminListenerTests(_Server):
    serves_internal = False

    def test_a_listener_that_does_not_serve_them_reports_absent_not_forbidden(self):
        # When the admin listener is configured, the MCP listener must look like a
        # gateway with no enrollment surface at all, not like one guarding it.
        for path, method in (("/internal/credentials", "GET"),
                             ("/internal/credentials", "POST"),
                             ("/internal/credentials", "DELETE"),
                             ("/internal/my-issues", "GET")):
            status, payload = self.call(path, method, body={"key": "good-key"} if method == "POST" else None)
            self.assertEqual(status, HTTPStatus.NOT_FOUND, f"{method} {path}")
            self.assertEqual(payload, {"error": "not found"})


if __name__ == "__main__":
    unittest.main()
