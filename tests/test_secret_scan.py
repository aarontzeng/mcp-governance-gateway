"""Secret-pattern scan: unit patterns + gateway wiring on team-visible writes."""

from __future__ import annotations

import unittest

from mcp_governance_gateway.auth import Principal
from mcp_governance_gateway.mcp import GatewayApp
from mcp_governance_gateway.secret_scan import find_secret

from test_phase1_mcp import FakeIssueBackend, FakeMemoryBackend, ListAuditSink

# Clearly fake, pattern-shaped specimens (never real credentials). Most are built
# by concatenation, so the credential-shaped literal never appears in the source and
# a repository secret scanner has nothing to match. The JWT cannot be split that way
# without stopping being a JWT -- its three segments are what the pattern tests --
# so it carries an explicit allow instead of being quietly excluded somewhere else.
FAKE_AWS = "AKIA" + "A" * 16
FAKE_GH = "ghp_" + "a1" * 18
FAKE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9P"  # gitleaks:allow
FAKE_PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIfake\n-----END RSA PRIVATE KEY-----"


class FindSecretTests(unittest.TestCase):
    def test_detects_the_secret_shaped_blobs(self):
        for text, label in [
            (f"deploy key is {FAKE_AWS} on the box", "AWS access key id"),
            (f"use {FAKE_GH} for the mirror", "GitHub token"),
            ("glpat-" + "x1" * 12, "GitLab personal access token"),
            ("xoxb-1234567890-abcdefghij", "Slack token"),
            ("AIza" + "B1" * 17 + "C", "Google API key"),
            ("sk-ant-api03-" + "z9" * 12, "sk-style API key"),
            (f"session was {FAKE_JWT}", "JWT"),
            ("Authorization: Bearer abc123def456ghi789jkl0", "bearer token"),
            (FAKE_PEM, "private key (PEM)"),
            ("db password=Sup3rSecretValue42", "credential assignment"),
        ]:
            self.assertEqual(find_secret(text), label, text)

    def test_ordinary_engineering_prose_stays_clean(self):
        for text in [
            "rotate MEMORY_BACKEND_TOKEN next quarter",         # var NAME, no value
            "raised TOKEN_EXPIRY from 20min to 8h",             # not a credential key
            "api_key=<from-env>",                               # placeholder
            "password=$DB_PASSWORD",                            # env reference
            "token: {{ vault.token }}",                         # template
            "user/password `user`/`password`",                  # doc prose
            "the bearer of this message",                       # no blob follows
            "set password=changeme then rotate",                # value too short
            "secret: MEMORY_BACKEND_TOKEN rotation deferred",   # no digit in value
            "issue #4210 assignee id 114 done_ratio 100",       # plain numbers, not values
            # Adversarial review, 2026-08-10: all four were rejected before the
            # value matcher required an unbroken run. Hyphenated words with a date
            # are 16+ chars with a digit, which the old pattern accepted as a blob.
            "token: rotation-window-2026-08-01",
            "api_key=not-configured-2026-08",
            # The allow below has to sit on the matched line itself, not above it.
            # gitleaks' generic-api-key rule flags this string -- which is the very
            # behaviour this list tests for: every entry here is a NEGATIVE case, a
            # piece of ordinary engineering prose that must not read as a credential.
            # A scanner matching one is demonstrating the failure, not finding a secret.
            "secret: pending-rotation-2026-Q3",  # gitleaks:allow
            "password: see-vault-entry-4210",
        ]:
            self.assertIsNone(find_secret(text), text)

    def test_a_credential_is_an_unbroken_blob_not_hyphenated_words(self):
        # The discriminator, stated as a test: same length, same digit, same key --
        # only the separators differ.
        self.assertEqual(find_secret("password=Sup3rSecretValue42"), "credential assignment")
        self.assertIsNone(find_secret("password=Sup3r-Secret-Value-42"))

    def test_scans_all_given_texts_and_skips_none(self):
        self.assertIsNone(find_secret(None, "", "clean"))
        self.assertEqual(find_secret("clean", None, FAKE_AWS), "AWS access key id")


class GatewayWiringTests(unittest.TestCase):
    def setUp(self):
        self.memory = FakeMemoryBackend()
        self.issues = FakeIssueBackend()
        self.app = GatewayApp(memory_backend=self.memory, audit_sink=ListAuditSink(), issue_backend=self.issues)
        self.principal = Principal(
            actor="user@example.com",
            project="example-project",
            roles=("issue_writer",),
            token_id="tok_1",
            issue_project="97",
        )

    def _call(self, name, arguments):
        return self.app.handle_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}},
            self.principal,
        )

    def _assert_rejected(self, resp):
        self.assertIn("possible secret detected", resp["error"]["message"])

    def test_memory_save_rejects_secret_in_text_and_tags(self):
        self._assert_rejected(self._call("memory.save", {"text": f"key {FAKE_AWS}"}))
        self._assert_rejected(self._call("memory.save", {"text": "clean", "tags": [FAKE_GH]}))
        self.assertEqual(self.memory.calls, [])  # nothing reached the backend

    def test_lesson_and_action_writes_are_scanned(self):
        self._assert_rejected(self._call("memory.lesson_save", {"rule": "clean", "reason": FAKE_PEM}))
        self._assert_rejected(self._call("memory.action_create", {"title": "t", "description": FAKE_JWT}))
        self.assertEqual(self.memory.calls, [])

    def test_issue_writes_reject_before_minting_a_confirmation(self):
        # the reject must come BEFORE the confirmation gate: no confirmationId leaks out
        resp = self._call("issues.create", {"subject": "s", "description": f"creds: {FAKE_AWS}"})
        self._assert_rejected(resp)
        resp = self._call("issues.add_note", {"id": 1, "note": f"see {FAKE_GH}"})
        self._assert_rejected(resp)
        self.assertEqual(self.issues.calls, [])

    def test_every_persisted_field_is_scanned_not_just_the_prose_ones(self):
        # Adversarial review, 2026-08-10: priority/tracker/assignee and the planning
        # fields were parsed but never scanned, and an AWS key id is exactly the 20
        # characters `priority` allows.
        self._assert_rejected(self._call("memory.action_create", {"title": "t", "priority": FAKE_AWS}))
        self.assertEqual(self.memory.calls, [])
        for field in ("tracker", "assignee", "priority", "category"):
            with self.subTest(field=field):
                resp = self._call("issues.create", {"subject": "s", field: FAKE_AWS})
                self._assert_rejected(resp)
                # ... and no confirmation was minted for a write that will not happen
                self.assertNotIn("result", resp)
        self.assertEqual(self.issues.calls, [])

    def test_update_status_scans_its_optional_fields_too(self):
        resp = self._call("issues.update_status", {"id": 1, "status": "RESOLVED", "assignee": FAKE_AWS})
        self._assert_rejected(resp)
        self.assertEqual(self.issues.calls, [])

    def test_clean_writes_still_pass(self):
        out = self._call("memory.save", {"text": "deployed image 2026-07-22-0dbf089, healthz ok"})
        self.assertTrue(out["result"]["structuredContent"]["saved"])
        first = self._call("issues.create", {"subject": "clean subject"})
        sc = first["result"]["structuredContent"]
        self.assertTrue(sc["confirmationRequired"])


if __name__ == "__main__":
    unittest.main()
