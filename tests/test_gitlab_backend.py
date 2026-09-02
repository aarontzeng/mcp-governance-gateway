from __future__ import annotations

import unittest
from typing import Any

from mcp_governance_gateway.gitlab_backend import GitLabHttpBackend, _iid, _state_filter
from mcp_governance_gateway.issue_backend import IssueBackendError
from mcp_governance_gateway.redmine_keystore import KeyState
from mcp_governance_gateway.memory_backend import RequestContext


def _ctx(issue_project="grp/app", actor="10000000"):
    return RequestContext(actor=actor, project="p", client="t", request_id="req-9", issue_project=issue_project)


PROJECT = {"id": 42, "name": "App", "path_with_namespace": "grp/app"}
ISSUE = {
    "iid": 7, "id": 9001, "project_id": 42, "title": "Crash on boot",
    "state": "opened", "issue_type": "issue", "updated_at": "2026-07-10T01:02:03Z",
    "assignee": {"id": 5, "name": "Alice"},
}


class FakeGitLab(GitLabHttpBackend):
    """Records requests; replies from a scripted table."""

    def __init__(self, replies: dict[tuple[str, str], Any] | None = None):
        super().__init__("https://gitlab.example", "TOKEN")
        self.calls: list[tuple[str, str, dict | None, dict | None]] = []
        self.replies = replies or {}

    def _request(self, method, path, *, params=None, body=None, token=None):
        self.calls.append((method, path, params, body))
        self.tokens = getattr(self, "tokens", [])
        self.tokens.append(token)
        key = (method, path)
        if key in self.replies:
            reply = self.replies[key]
            if isinstance(reply, IssueBackendError):
                raise reply
            return reply
        if method == "GET" and path == "/projects/grp%2Fapp":
            return PROJECT
        if method == "GET" and path == "/projects/42/issues/7":
            return ISSUE
        return {}


class GetTests(unittest.TestCase):
    def test_get_normalizes(self):
        out = FakeGitLab().get("7", _ctx())
        self.assertEqual(out["id"], "7")            # project-scoped iid, not global id
        self.assertEqual(out["projectId"], "42")
        self.assertEqual(out["projectName"], "App")
        self.assertEqual(out["status"], "OPEN")
        self.assertEqual(out["tracker"], "ISSUE")
        self.assertEqual(out["assignee"], {"id": "5", "displayName": "Alice"})
        self.assertIsNone(out["doneRatio"])

    def test_get_accepts_hash_prefix_and_rejects_nonnumeric(self):
        self.assertEqual(FakeGitLab().get("#7", _ctx())["id"], "7")
        with self.assertRaises(ValueError):
            FakeGitLab().get("7; rm -rf", _ctx())

    def test_foreign_project_issue_is_404(self):
        wrong = dict(ISSUE, project_id=99)
        fake = FakeGitLab({("GET", "/projects/42/issues/7"): wrong})
        with self.assertRaises(IssueBackendError) as cm:
            fake.get("7", _ctx())
        self.assertEqual(cm.exception.status, 404)

    def test_numeric_project_key_used_verbatim(self):
        fake = FakeGitLab({("GET", "/projects/42"): PROJECT})
        out = fake.get("7", _ctx(issue_project="42"))
        self.assertEqual(out["projectId"], "42")


class SearchTests(unittest.TestCase):
    def test_search_scopes_and_filters(self):
        items = [ISSUE, dict(ISSUE, iid=8, project_id=99), "junk", dict(ISSUE, iid=9, state="closed")]
        fake = FakeGitLab({("GET", "/projects/42/issues"): items})
        out = fake.search({"status": "open"}, 10, _ctx())
        self.assertEqual([i["id"] for i in out["issues"]], ["7", "9"])  # 8 dropped (foreign project)
        method, path, params, _ = fake.calls[-1]
        self.assertEqual(params["state"], "opened")

    def test_assignee_numeric_vs_username(self):
        fake = FakeGitLab({("GET", "/projects/42/issues"): []})
        fake.search({"assignee": "5"}, 5, _ctx())
        self.assertEqual(fake.calls[-1][2].get("assignee_id"), "5")
        fake.search({"assignee": "alice"}, 5, _ctx())
        self.assertEqual(fake.calls[-1][2].get("assignee_username"), "alice")

    def test_state_filter_values(self):
        self.assertEqual(_state_filter("open"), "opened")
        self.assertEqual(_state_filter("CLOSED".lower()), "closed")
        self.assertEqual(_state_filter("*"), "all")
        with self.assertRaises(ValueError):
            _state_filter("IN_PROGRESS")


class WriteTests(unittest.TestCase):
    def test_create_carries_attribution(self):
        created = dict(ISSUE, iid=11, title="New thing")
        fake = FakeGitLab({("POST", "/projects/42/issues"): created})
        out = fake.create({"subject": "New thing", "description": "details"}, _ctx())
        self.assertTrue(out["created"])
        self.assertEqual(out["id"], "11")
        body = fake.calls[-1][3]
        self.assertEqual(body["title"], "New thing")
        self.assertIn("details", body["description"])
        self.assertIn("[via mcp-governance-gateway | actor=10000000 | audit=req-9]", body["description"])

    def test_create_in_wrong_project_fails_closed(self):
        fake = FakeGitLab({("POST", "/projects/42/issues"): dict(ISSUE, project_id=99)})
        with self.assertRaises(IssueBackendError):
            fake.create({"subject": "x"}, _ctx())

    def test_add_note_verifies_project_and_stamps(self):
        fake = FakeGitLab()
        out = fake.add_note("7", "progress", _ctx())
        self.assertEqual(out, {"noted": True, "id": "7"})
        method, path, _, body = fake.calls[-1]
        self.assertEqual((method, path), ("POST", "/projects/42/issues/7/notes"))
        self.assertIn("progress", body["body"])
        self.assertIn("actor=10000000", body["body"])

    def test_update_status_close_and_reopen(self):
        fake = FakeGitLab()
        out = fake.update_status("7", "closed", None, _ctx())
        self.assertEqual(out["status"], "CLOSED")
        self.assertIn(("PUT", "/projects/42/issues/7"), [(m, p) for m, p, _, _ in fake.calls])
        put_body = [b for m, p, _, b in fake.calls if (m, p) == ("PUT", "/projects/42/issues/7")][0]
        self.assertEqual(put_body, {"state_event": "close"})
        out = fake.update_status("7", "OPEN", None, _ctx())
        self.assertEqual(out["status"], "OPEN")

    def test_update_status_rejects_workflow_names_and_done_ratio(self):
        with self.assertRaises(ValueError):
            FakeGitLab().update_status("7", "RESOLVED", None, _ctx())
        with self.assertRaises(ValueError):
            FakeGitLab().update_status("7", "closed", 50, _ctx())


class PersonalTokenTests(unittest.TestCase):
    def test_personal_pat_routes_the_write_and_trims_footer(self):
        fake = FakeGitLab()
        fake._key_resolver = lambda actor: (KeyState.OK, "PAT-OF-USER")
        out = fake.add_note("7", "hi", _ctx())
        self.assertEqual(out["noted"], True)
        method, path, _, body = fake.calls[-1]
        self.assertEqual(path, "/projects/42/issues/7/notes")
        self.assertEqual(fake.tokens[-1], "PAT-OF-USER")          # write on the personal PAT
        self.assertNotIn("actor=", body["body"])                   # personal → footer trimmed to audit id
        self.assertIn("audit=req-9", body["body"])
        # non-authorship verify stayed on the shared token (token=None → default)
        verify_idx = [i for i, (m, p, _, _) in enumerate(fake.calls) if p == "/projects/42/issues/7"][0]
        self.assertIsNone(fake.tokens[verify_idx])

    def test_enforced_without_key_fails_428(self):
        fake = FakeGitLab()
        fake._key_resolver = lambda actor: (KeyState.MISSING, None)
        fake._enforce_personal = True
        with self.assertRaises(IssueBackendError) as cm:
            fake.create({"subject": "x"}, _ctx())
        self.assertEqual(cm.exception.status, 428)
        self.assertEqual(fake.calls, [])  # failed loud before touching the backend

    def test_undecryptable_fails_409(self):
        fake = FakeGitLab()
        fake._key_resolver = lambda actor: (KeyState.UNDECRYPTABLE, None)
        with self.assertRaises(IssueBackendError) as cm:
            fake.add_note("7", "x", _ctx())
        self.assertEqual(cm.exception.status, 409)

    def test_degraded_store_is_a_503_not_an_enrollment_prompt(self):
        # A degraded keystore is a server-side condition; the Redmine backend says
        # so with a 503, and telling a GitLab caller to "enroll" would send them to
        # fix something they cannot. Enforced writes and issues.mine both fail
        # closed the same way; an optional-mode write still falls back (attributed).
        fake = FakeGitLab()
        fake._key_resolver = lambda actor: (KeyState.DEGRADED, None)
        fake._enforce_personal = True
        with self.assertRaises(IssueBackendError) as cm:
            fake.create({"subject": "x"}, _ctx())
        self.assertEqual(cm.exception.status, 503)
        self.assertNotIn("enroll it", str(cm.exception))
        with self.assertRaises(IssueBackendError) as cm:
            fake.mine(10, _ctx())
        self.assertEqual(cm.exception.status, 503)
        self.assertEqual(fake.calls, [])
        fake._enforce_personal = False
        self.assertEqual(fake._write_key(_ctx()), (fake._token, False))

    def test_verify_key_shape_matches_redmine(self):
        fake = FakeGitLab({("GET", "/user"): {"id": 9, "username": "alice", "email": "alice@example.com"}})
        out = fake.verify_key("PAT")
        self.assertEqual(out, {"id": 9, "login": "alice", "mail": "alice@example.com"})
        self.assertEqual(fake.tokens[-1], "PAT")  # verified on the submitted PAT itself

    def test_list_assigned_to_me_uses_personal_token_and_scope(self):
        fake = FakeGitLab({("GET", "/projects/42/issues"): [ISSUE]})
        out = fake.list_assigned_to_me("PAT", _ctx())
        self.assertEqual(out["count"], 1)
        m, p, params, _ = fake.calls[-1]
        self.assertEqual(params["scope"], "assigned_to_me")
        self.assertEqual(fake.tokens[-1], "PAT")


class RedmineOnlyFieldTests(unittest.TestCase):
    """Fields with no GitLab equivalent are refused, never silently dropped."""

    def test_planning_fields_are_refused_by_name_on_every_write_path(self):
        # Adversarial review, 2026-08-10: update_status refused them, create silently
        # dropped them -- so a confirmed create produced an issue missing the due
        # date, parent and category the caller asked for, with no error.
        for call in (
            lambda f: f.update_status("7", "closed", None, _ctx(),
                                      planning={"dueDate": "2026-09-01", "category": "Firmware"}),
            lambda f: f.create({"subject": "s", "dueDate": "2026-09-01", "category": "Firmware"}, _ctx()),
        ):
            fake = FakeGitLab()
            with self.subTest(path=call):
                with self.assertRaises(ValueError) as cm:
                    call(fake)
                message = str(cm.exception)
                self.assertIn("dueDate", message)
                self.assertIn("category", message)
                self.assertEqual(fake.calls, [])  # refused before touching GitLab

    def test_a_create_without_redmine_only_fields_still_works(self):
        fake = FakeGitLab({("POST", "/projects/42/issues"): {"iid": 8, "project_id": 42, "title": "t"}})
        self.assertTrue(fake.create({"subject": "t", "assignee": "alice"}, _ctx())["created"])

    def test_categories_says_what_gitlab_has_instead(self):
        with self.assertRaises(IssueBackendError) as cm:
            FakeGitLab().categories(_ctx())
        self.assertEqual(cm.exception.status, 400)
        self.assertIn("labels", str(cm.exception))

    def test_normalized_shape_keeps_the_category_key_as_none(self):
        # The shape stays identical across backends so a caller need not branch.
        out = FakeGitLab().get("7", _ctx())
        self.assertIsNone(out["category"])
        self.assertIn("description", out)


class AssigneeFieldTests(unittest.TestCase):
    def test_numeric_id_and_username_take_different_parameters(self):
        fake = FakeGitLab({("POST", "/projects/42/issues"): {"iid": 8, "project_id": 42, "title": "t"}})
        fake.create({"subject": "t", "assignee": "42"}, _ctx())
        self.assertEqual(fake.calls[-1][3]["assignee_id"], "42")
        fake.create({"subject": "t", "assignee": "alice"}, _ctx())
        self.assertEqual(fake.calls[-1][3]["assignee_username"], "alice")

    def test_update_status_can_reassign(self):
        fake = FakeGitLab()
        fake.update_status("7", "closed", None, _ctx(), assignee="alice")
        put = [c for c in fake.calls if c[0] == "PUT"][0]
        self.assertEqual(put[3]["assignee_username"], "alice")


class MineTests(unittest.TestCase):
    def test_mine_never_answers_from_the_shared_token(self):
        fake = FakeGitLab()
        fake._key_resolver = None
        with self.assertRaises(IssueBackendError) as cm:
            fake.mine(10, _ctx())
        self.assertEqual(cm.exception.status, 428)
        fake._key_resolver = lambda actor: (KeyState.MISSING, None)
        with self.assertRaises(IssueBackendError) as cm:
            fake.mine(10, _ctx())
        self.assertEqual(cm.exception.status, 428)
        self.assertEqual(fake.calls, [])

    def test_mine_uses_the_personal_pat(self):
        fake = FakeGitLab({("GET", "/projects/42/issues"): [ISSUE]})
        fake._key_resolver = lambda actor: (KeyState.OK, "PAT")
        out = fake.mine(10, _ctx())
        self.assertEqual(out["count"], 1)
        self.assertEqual(fake.tokens[-1], "PAT")


class CredentialPortalHintTests(unittest.TestCase):
    """Same contract as the Redmine backend: the enrollment errors carry the
    deployment's portal URL when there is one, and no host when there is not."""

    def _message(self, portal):
        fake = FakeGitLab()
        fake._portal_url = (portal or "").rstrip("/") or None
        fake._key_resolver = lambda actor: (KeyState.UNDECRYPTABLE, None)
        with self.assertRaises(IssueBackendError) as cm:
            fake.add_note("7", "x", _ctx())
        return str(cm.exception)

    def test_no_url_when_unconfigured(self):
        message = self._message(None)
        self.assertIn("credential-enrollment endpoint", message)
        self.assertNotIn("http", message)

    def test_url_appended_when_configured(self):
        self.assertTrue(self._message("https://gateway.example/admin/").endswith(" -> https://gateway.example/admin"))


class HelperTests(unittest.TestCase):
    def test_iid(self):
        self.assertEqual(_iid("#12"), "12")
        with self.assertRaises(ValueError):
            _iid("abc")


if __name__ == "__main__":
    unittest.main()
