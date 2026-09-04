"""`mcpgw-admin`, the reference minter.

Every test drives `main(argv)` rather than the functions under it: the argument
surface is the contract an operator actually touches, and a test that calls
`cmd_mint` directly proves nothing about whether `--actor` is required.
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from mcp_governance_gateway.admin_cli import main
from mcp_governance_gateway.auth import BearerTokenAuthenticator


class _CliTestCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.store = Path(self.dir.name) / "user-tokens.json"
        for name in ("GATEWAY_USER_TOKEN_FILE", "GATEWAY_TOKEN_FILE"):
            os.environ.pop(name, None)

    def run_cli(self, *argv, capture=True):
        import io
        import contextlib
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["--store", str(self.store), *argv])
        self.assertEqual(code, 0)
        return out.getvalue().strip(), err.getvalue()

    def entries(self):
        return json.loads(self.store.read_text(encoding="utf-8"))["tokens"]


class MintTests(_CliTestCase):
    def test_a_minted_token_is_a_token_the_gateway_can_resolve(self):
        # The point of the tool: what it writes must load through the real
        # authenticator, not merely look like JSON.
        token, _ = self.run_cli("mint", "--actor", "10000001", "--project", "team-a",
                                "--issue-project", "demo", "--role", "issue_writer",
                                "--email", "a@example.com", "--name", "A")
        principal = BearerTokenAuthenticator.from_file(self.store).authenticate_header(f"Bearer {token}")
        self.assertEqual(principal.actor, "10000001")
        self.assertEqual(principal.project, "team-a")
        self.assertEqual(principal.issue_project, "demo")
        self.assertEqual(principal.roles, ("issue_writer",))
        self.assertEqual(principal.email, "a@example.com")

    def test_the_token_is_random_and_long(self):
        first, _ = self.run_cli("mint", "--actor", "1", "--project", "p")
        second, _ = self.run_cli("mint", "--actor", "2", "--project", "p")
        self.assertNotEqual(first, second)
        self.assertGreaterEqual(len(first), 40)   # token_urlsafe(32)

    def test_the_token_is_printed_once_on_stdout_and_never_by_list(self):
        token, _ = self.run_cli("mint", "--actor", "1", "--project", "p")
        listing_out, listing_err = self.run_cli("list")
        self.assertNotIn(token, listing_out + listing_err)
        self.assertIn("1", listing_out)

    def test_the_store_is_written_atomically_and_owner_only(self):
        self.run_cli("mint", "--actor", "1", "--project", "p")
        mode = stat.S_IMODE(self.store.stat().st_mode)
        self.assertEqual(mode, 0o600, oct(mode))
        self.assertEqual(list(Path(self.dir.name).glob("*.tmp")), [])   # no leftovers

    def test_minting_twice_for_the_same_actor_and_project_is_refused(self):
        self.run_cli("mint", "--actor", "1", "--project", "p")
        with self.assertRaises(SystemExit) as caught:
            main(["--store", str(self.store), "mint", "--actor", "1", "--project", "p"])
        self.assertIn("rotate", str(caught.exception))

    def test_the_same_actor_may_hold_a_token_per_project(self):
        self.run_cli("mint", "--actor", "1", "--project", "p")
        self.run_cli("mint", "--actor", "1", "--project", "q")
        self.assertEqual(len(self.entries()), 2)

    def test_actor_is_required_and_never_defaulted(self):
        # ADR-0007 wants a VERIFIED immutable id. A value this tool guessed from
        # $USER would be neither, so there is no default to guess from.
        os.environ["USER"] = "aaron"
        with self.assertRaises(SystemExit):
            main(["--store", str(self.store), "mint", "--project", "p"])
        self.assertFalse(self.store.exists())


class RotateAndRevokeTests(_CliTestCase):
    def setUp(self):
        super().setUp()
        self.token, _ = self.run_cli("mint", "--actor", "1", "--project", "p", "--role", "issue_writer")

    def test_rotate_replaces_the_token_and_keeps_everything_else(self):
        new, err = self.run_cli("rotate", "--actor", "1", "--project", "p")
        self.assertNotEqual(new, self.token)
        self.assertIn("rotated", err)
        entry = self.entries()[0]
        self.assertEqual(entry["roles"], ["issue_writer"])
        auth = BearerTokenAuthenticator.from_file(self.store)
        self.assertEqual(auth.authenticate_header(f"Bearer {new}").actor, "1")
        with self.assertRaises(Exception):
            auth.authenticate_header(f"Bearer {self.token}")

    def test_revoke_removes_the_entry(self):
        self.run_cli("revoke", "--actor", "1", "--project", "p")
        self.assertEqual(self.entries(), [])

    def test_revoking_something_that_is_not_there_is_an_error_not_a_silent_success(self):
        with self.assertRaises(SystemExit):
            main(["--store", str(self.store), "revoke", "--actor", "nope", "--project", "p"])

    def test_roles_can_be_granted_and_taken_away(self):
        self.run_cli("grant", "--actor", "1", "--project", "p", "--role", "docs_writer")
        self.assertEqual(self.entries()[0]["roles"], ["docs_writer", "issue_writer"])
        self.run_cli("revoke-role", "--actor", "1", "--project", "p", "--role", "issue_writer")
        self.assertEqual(self.entries()[0]["roles"], ["docs_writer"])


class StoreSafetyTests(_CliTestCase):
    def test_it_refuses_to_write_the_operator_managed_static_store(self):
        # GATEWAY_TOKEN_FILE is hand-managed and often under configuration
        # management; rewriting it from here would silently reformat it.
        static = Path(self.dir.name) / "static.json"
        static.write_text(json.dumps({"tokens": []}), encoding="utf-8")
        os.environ["GATEWAY_TOKEN_FILE"] = str(static)
        self.addCleanup(os.environ.pop, "GATEWAY_TOKEN_FILE", None)
        with self.assertRaises(SystemExit) as caught:
            main(["--store", str(static), "mint", "--actor", "1", "--project", "p"])
        self.assertIn("operator-managed", str(caught.exception))
        self.assertEqual(json.loads(static.read_text(encoding="utf-8")), {"tokens": []})

    def test_the_store_defaults_to_the_env_var_the_gateway_reads(self):
        os.environ["GATEWAY_USER_TOKEN_FILE"] = str(self.store)
        self.addCleanup(os.environ.pop, "GATEWAY_USER_TOKEN_FILE", None)
        self.assertEqual(main(["mint", "--actor", "1", "--project", "p"]), 0)
        self.assertTrue(self.store.exists())

    def test_no_store_at_all_is_an_error_not_a_guess(self):
        with self.assertRaises(SystemExit):
            main(["mint", "--actor", "1", "--project", "p"])

    def test_a_store_that_is_not_a_token_file_is_refused_rather_than_overwritten(self):
        self.store.write_text(json.dumps({"something": "else"}), encoding="utf-8")
        with self.assertRaises(SystemExit):
            main(["--store", str(self.store), "mint", "--actor", "1", "--project", "p"])
        self.assertEqual(json.loads(self.store.read_text(encoding="utf-8")), {"something": "else"})

    def test_an_existing_store_is_extended_not_replaced(self):
        self.run_cli("mint", "--actor", "1", "--project", "p")
        self.run_cli("mint", "--actor", "2", "--project", "p")
        self.assertEqual({e["actor"] for e in self.entries()}, {"1", "2"})


if __name__ == "__main__":
    unittest.main()
