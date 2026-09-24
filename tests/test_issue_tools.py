"""The issue tools and the Redmine adapter behind them: tenancy, per-caller keys, write fields, confirmations."""
from __future__ import annotations

import json
import unittest

from fakes import FakeIssueBackend, FakeMemoryBackend, FakeResponse

from mcp_governance_gateway.audit import ListAuditSink
from mcp_governance_gateway.auth import Principal
from mcp_governance_gateway.confirm import ConfirmationStore
from mcp_governance_gateway.issue_backend import IssueBackendError, RedmineHttpBackend
from mcp_governance_gateway.mcp import GatewayApp
from mcp_governance_gateway.memory_backend import RequestContext
from mcp_governance_gateway.redmine_keystore import KeyState


class IssueToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.issues = FakeIssueBackend()
        self.audit = ListAuditSink()
        self.app = GatewayApp(
            memory_backend=FakeMemoryBackend(),
            audit_sink=self.audit,
            issue_backend=self.issues,
            confirmation=ConfirmationStore(clock=lambda: 1000.0),
        )
        self.principal = Principal(
            actor="u@x", project="proj", roles=("developer", "issue_writer"),
            token_id="t", issue_project="97",
        )
        self.reader = Principal(
            actor="r@x", project="proj", roles=("developer",), token_id="t2", issue_project="97",
        )
        self.no_redmine = Principal(actor="u@x", project="proj", roles=("developer",), token_id="t")

    def _call(self, name: str, arguments: dict, principal: Principal | None = None):
        return self.app.handle_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}},
            principal or self.principal,
        )

    def test_issue_tool_denied_without_redmine_project(self) -> None:
        response = self._call("issues.get", {"id": "1"}, self.no_redmine)
        assert response is not None
        self.assertEqual(response["error"]["code"], -32003)
        self.assertEqual(self.issues.calls, [])
        self.assertEqual(self.audit.events[-1].reason, "token has no issue project")

    def test_issue_get_is_scoped_to_token_project_and_audited(self) -> None:
        response = self._call("issues.get", {"id": "123"})
        assert response is not None
        self.assertEqual(response["result"]["structuredContent"]["id"], "123")
        self.assertEqual(self.issues.calls[0], ("get", "123", "97"))
        self.assertEqual(self.audit.events[-1].outcome, "ok")
        self.assertEqual(self.audit.events[-1].tool, "issues.get")

    def test_issue_search_injects_token_redmine_project(self) -> None:
        response = self._call("issues.search", {"status": "open", "limit": 5})
        assert response is not None
        self.assertEqual(self.issues.calls[0][0], "search")
        self.assertEqual(self.issues.calls[0][3], "97")

    def test_create_requires_confirmation_then_commits(self) -> None:
        first = self._call("issues.create", {"subject": "New bug"})
        assert first is not None
        sc = first["result"]["structuredContent"]
        self.assertTrue(sc["confirmationRequired"])
        self.assertEqual(self.issues.calls, [])
        self.assertEqual(self.audit.events[-1].outcome, "confirm_required")

        second = self._call("issues.create", {"subject": "New bug", "confirm": sc["confirmationId"]})
        assert second is not None
        self.assertTrue(second["result"]["structuredContent"]["created"])
        self.assertEqual(self.issues.calls[0][0], "create")
        self.assertEqual(self.audit.events[-1].outcome, "ok")

    def test_create_with_wrong_confirm_does_not_execute(self) -> None:
        response = self._call("issues.create", {"subject": "X", "confirm": "bogus"})
        assert response is not None
        self.assertTrue(response["result"]["structuredContent"]["confirmationRequired"])
        self.assertEqual(self.issues.calls, [])

    def test_confirmation_token_is_bound_to_arguments(self) -> None:
        first = self._call("issues.create", {"subject": "A"})
        assert first is not None
        cid = first["result"]["structuredContent"]["confirmationId"]
        # reuse A's token for a different subject -> must not commit
        response = self._call("issues.create", {"subject": "B", "confirm": cid})
        assert response is not None
        self.assertTrue(response["result"]["structuredContent"]["confirmationRequired"])
        self.assertEqual(self.issues.calls, [])

    def test_update_status_confirm_and_commit(self) -> None:
        first = self._call("issues.update_status", {"id": "12", "status": "RESOLVED", "doneRatio": 100})
        assert first is not None
        cid = first["result"]["structuredContent"]["confirmationId"]
        second = self._call(
            "issues.update_status", {"id": "12", "status": "RESOLVED", "doneRatio": 100, "confirm": cid}
        )
        assert second is not None
        self.assertTrue(second["result"]["structuredContent"]["updated"])
        self.assertEqual(self.issues.calls[0], ("update_status", "12", "RESOLVED", 100, None, {}))

    def test_destructive_issue_tool_denied(self) -> None:
        response = self._call("issues.delete", {"id": "1"})
        assert response is not None
        self.assertEqual(response["error"]["code"], -32003)
        self.assertEqual(self.audit.events[-1].reason, "destructive operations are denied")

    def test_tools_list_includes_issue_tools(self) -> None:
        response = self.app.handle_rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, self.principal)
        assert response is not None
        names = [tool["name"] for tool in response["result"]["tools"]]
        for expected in ("issues.get", "issues.search", "issues.create", "issues.add_note", "issues.update_status"):
            self.assertIn(expected, names)

    def test_write_denied_without_issue_writer_role(self) -> None:
        response = self._call("issues.create", {"subject": "x"}, self.reader)
        assert response is not None
        self.assertEqual(response["error"]["code"], -32003)
        self.assertEqual(self.issues.calls, [])
        self.assertEqual(self.audit.events[-1].reason, "token lacks issue write role")

    def test_reader_role_can_still_read(self) -> None:
        response = self._call("issues.get", {"id": "5"}, self.reader)
        assert response is not None
        self.assertEqual(response["result"]["structuredContent"]["id"], "5")

    def test_confirmation_is_single_use(self) -> None:
        first = self._call("issues.create", {"subject": "once"})
        assert first is not None
        cid = first["result"]["structuredContent"]["confirmationId"]
        committed = self._call("issues.create", {"subject": "once", "confirm": cid})
        assert committed is not None
        self.assertTrue(committed["result"]["structuredContent"]["created"])
        # replay the same confirmation token -> must be rejected (re-prompt, not executed)
        replay = self._call("issues.create", {"subject": "once", "confirm": cid})
        assert replay is not None
        self.assertTrue(replay["result"]["structuredContent"]["confirmationRequired"])
        self.assertEqual(len(self.issues.calls), 1)

    def test_tools_list_filters_by_role_and_backend(self) -> None:
        reader_list = self.app.handle_rpc({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}, self.reader)
        assert reader_list is not None
        reader_names = [t["name"] for t in reader_list["result"]["tools"]]
        self.assertIn("issues.get", reader_names)
        self.assertNotIn("issues.create", reader_names)  # no issue_writer role

        none_list = self.app.handle_rpc({"jsonrpc": "2.0", "id": 4, "method": "tools/list"}, self.no_redmine)
        assert none_list is not None
        none_names = [t["name"] for t in none_list["result"]["tools"]]
        self.assertEqual(none_names, ["memory.search", "memory.save", "memory.list", "memory.lesson_save", "memory.lesson_list", "memory.action_create", "memory.action_list", "memory.action_update_status"])  # no redmine_project


# Statuses as a non-stock instance reports them: ids are shuffled away from the
# 1..6 a fresh Redmine seeds, and PENDING is a custom status. A test that expects
# the right id here can only be reading it from the instance.
_STATUS_ROWS = {
    "issue_statuses": [
        {"id": 7, "name": "New"},
        {"id": 19, "name": "In Progress"},
        {"id": 42, "name": "Resolved"},
        {"id": 5, "name": "Closed"},
        {"id": 88, "name": "Pending Review"},
    ]
}


class RedmineHttpBackendTests(unittest.TestCase):
    def _backend_with(self, router):  # type: ignore[no-untyped-def]
        from mcp_governance_gateway import http_client

        original = http_client.request.urlopen
        http_client.request.urlopen = router
        self.addCleanup(lambda: setattr(http_client.request, "urlopen", original))
        return RedmineHttpBackend(base_url="http://redmine.internal/redmine", api_key="k")

    @staticmethod
    def _ctx() -> RequestContext:
        return RequestContext(actor="u", project="p", client="t", request_id="r", issue_project="97")

    def test_get_enforces_project_scope_and_normalizes(self) -> None:
        def router(req, timeout):  # type: ignore[no-untyped-def]
            url = req.full_url
            if "/projects/97.json" in url:
                return FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issues/123.json" in url:
                return FakeResponse(
                    {
                        "issue": {
                            "id": 123,
                            "project": {"id": 97, "name": "Q"},
                            "subject": "S",
                            "status": {"name": "In Progress"},
                            "tracker": {"name": "Bug"},
                            "done_ratio": 50,
                        }
                    }
                )
            raise AssertionError(url)

        backend = self._backend_with(router)
        issue = backend.get("123", self._ctx())
        self.assertEqual(issue["id"], "123")
        self.assertEqual(issue["projectId"], "97")
        self.assertEqual(issue["status"], "IN_PROGRESS")
        self.assertEqual(issue["tracker"], "BUG")

    def test_get_rejects_issue_from_another_project(self) -> None:
        def router(req, timeout):  # type: ignore[no-untyped-def]
            url = req.full_url
            if "/projects/97.json" in url:
                return FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issues/999.json" in url:
                return FakeResponse({"issue": {"id": 999, "project": {"id": 55, "name": "Other"}, "subject": "X"}})
            raise AssertionError(url)

        backend = self._backend_with(router)
        with self.assertRaises(IssueBackendError) as cm:
            backend.get("999", self._ctx())
        self.assertEqual(cm.exception.status, 404)

    def test_search_forces_project_and_maps_status_filter(self) -> None:
        captured: dict[str, str] = {}

        def router(req, timeout):  # type: ignore[no-untyped-def]
            url = req.full_url
            if "/projects/97.json" in url:
                return FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issues.json" in url:
                captured["url"] = url
                return FakeResponse(
                    {"issues": [{"id": 1, "project": {"id": 97, "name": "Q"}, "subject": "a", "status": {"name": "New"}}]}
                )
            raise AssertionError(url)

        backend = self._backend_with(router)
        result = backend.search({"status": "open"}, 10, self._ctx())
        self.assertEqual(result["count"], 1)
        self.assertIn("project_id=97", captured["url"])
        self.assertIn("status_id=open", captured["url"])

    def test_create_injects_attribution_into_description(self) -> None:
        captured: dict[str, object] = {}

        def router(req, timeout):  # type: ignore[no-untyped-def]
            url = req.full_url
            if "/projects/97.json" in url:
                return FakeResponse({"project": {"id": 97, "name": "Q"}})
            if url.endswith("/issues.json") and req.get_method() == "POST":
                captured["body"] = json.loads(req.data.decode("utf-8"))
                return FakeResponse({"issue": {"id": 500, "project": {"id": 97, "name": "Q"}, "subject": "New"}})
            raise AssertionError((req.get_method(), url))

        backend = self._backend_with(router)
        result = backend.create({"subject": "New", "description": "do X"}, self._ctx())
        self.assertTrue(result["created"])
        desc = captured["body"]["issue"]["description"]  # type: ignore[index]
        self.assertIn("do X", desc)
        self.assertIn("actor=u", desc)
        self.assertIn("audit=r", desc)

    def test_add_note_appends_attribution(self) -> None:
        captured: dict[str, object] = {}

        def router(req, timeout):  # type: ignore[no-untyped-def]
            url, method = req.full_url, req.get_method()
            if "/projects/97.json" in url:
                return FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issues/55.json" in url and method == "GET":
                return FakeResponse({"issue": {"id": 55, "project": {"id": 97, "name": "Q"}}})
            if "/issues/55.json" in url and method == "PUT":
                captured["body"] = json.loads(req.data.decode("utf-8"))
                return FakeResponse({})
            raise AssertionError((method, url))

        backend = self._backend_with(router)
        result = backend.add_note("55", "please review", self._ctx())
        self.assertTrue(result["noted"])
        notes = captured["body"]["issue"]["notes"]  # type: ignore[index]
        self.assertIn("please review", notes)
        self.assertIn("actor=u", notes)

    def test_update_status_records_attribution_note(self) -> None:
        captured: dict[str, object] = {}

        def router(req, timeout):  # type: ignore[no-untyped-def]
            url, method = req.full_url, req.get_method()
            if "/issue_statuses.json" in url:
                return FakeResponse(_STATUS_ROWS)
            if "/projects/97.json" in url:
                return FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issues/12.json" in url and method == "GET":
                return FakeResponse({"issue": {"id": 12, "project": {"id": 97, "name": "Q"}}})
            if "/issues/12.json" in url and method == "PUT":
                captured["body"] = json.loads(req.data.decode("utf-8"))
                return FakeResponse({})
            raise AssertionError((method, url))

        backend = self._backend_with(router)
        result = backend.update_status("12", "RESOLVED", 100, self._ctx())
        self.assertEqual(result["status"], "RESOLVED")
        body = captured["body"]["issue"]  # type: ignore[index]
        # 42, not a stock 3: the id is whatever this instance reports for the name.
        self.assertEqual(body["status_id"], 42)
        self.assertEqual(body["done_ratio"], 100)
        self.assertIn("actor=u", body["notes"])

    def test_search_drops_items_from_other_projects(self) -> None:
        def router(req, timeout):  # type: ignore[no-untyped-def]
            url = req.full_url
            if "/projects/97.json" in url:
                return FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issues.json" in url:
                return FakeResponse({"issues": [
                    {"id": 1, "project": {"id": 97, "name": "Q"}, "subject": "mine", "status": {"name": "New"}},
                    {"id": 2, "project": {"id": 55, "name": "Other"}, "subject": "leak", "status": {"name": "New"}},
                ]})
            raise AssertionError(url)

        backend = self._backend_with(router)
        result = backend.search({}, 10, self._ctx())
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["issues"][0]["id"], "1")

    def test_create_fails_closed_on_project_mismatch(self) -> None:
        def router(req, timeout):  # type: ignore[no-untyped-def]
            url = req.full_url
            if "/projects/97.json" in url:
                return FakeResponse({"project": {"id": 97, "name": "Q"}})
            if url.endswith("/issues.json") and req.get_method() == "POST":
                return FakeResponse({"issue": {"id": 7, "project": {"id": 55, "name": "Other"}, "subject": "X"}})
            raise AssertionError((req.get_method(), url))

        backend = self._backend_with(router)
        with self.assertRaises(IssueBackendError):
            backend.create({"subject": "X", "description": None}, self._ctx())

    def test_normalize_issue_tolerates_hostile_field_types(self) -> None:
        from mcp_governance_gateway.issue_backend import _normalize_issue

        out = _normalize_issue(
            {"id": 1, "project": "not-a-dict", "status": 7, "tracker": ["x"], "assigned_to": "nope"}
        )
        self.assertEqual(out["status"], "")
        self.assertEqual(out["tracker"], "")
        self.assertEqual(out["projectId"], "")
        self.assertIsNone(out["assignee"])

    def test_request_rejects_oversized_response(self) -> None:
        big = {"issues": [], "junk": "x" * 2_000_001}

        def router(req, timeout):  # type: ignore[no-untyped-def]
            url = req.full_url
            if "/projects/97.json" in url:
                return FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issues.json" in url:
                return FakeResponse(big)
            raise AssertionError(url)

        backend = self._backend_with(router)
        with self.assertRaises(IssueBackendError):
            backend.search({}, 5, self._ctx())

    def test_request_rejects_invalid_utf8(self) -> None:
        class _RawResp:
            def __enter__(self):  # type: ignore[no-untyped-def]
                return self

            def __exit__(self, *a):  # type: ignore[no-untyped-def]
                return None

            def read(self, *a):  # type: ignore[no-untyped-def]
                return b"\xff\xfe\xff"

        def router(req, timeout):  # type: ignore[no-untyped-def]
            url = req.full_url
            if "/projects/97.json" in url:
                return FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issues.json" in url:
                return _RawResp()
            raise AssertionError(url)

        backend = self._backend_with(router)
        with self.assertRaises(IssueBackendError):
            backend.search({}, 5, self._ctx())


class StatusIdResolutionTests(unittest.TestCase):
    """Status ids are read from the instance, never hardcoded.

    A fixed table is not merely inelegant here: an instance that added, removed or
    reordered statuses would silently be written into the *wrong* state, because a
    valid-looking id always succeeds.
    """

    def _backend(self, rows=_STATUS_ROWS):
        from mcp_governance_gateway import http_client

        self.fetches: list[str] = []
        self.rows = rows

        def router(req, timeout):  # type: ignore[no-untyped-def]
            url, method = req.full_url, req.get_method()
            if "/issue_statuses.json" in url:
                self.fetches.append(url)
                return FakeResponse(self.rows)
            if "/projects/97.json" in url:
                return FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issues/12.json" in url and method == "GET":
                return FakeResponse({"issue": {"id": 12, "project": {"id": 97, "name": "Q"}}})
            if "/issues/12.json" in url and method == "PUT":
                self.put = json.loads(req.data.decode("utf-8"))
                return FakeResponse({})
            raise AssertionError((method, url))

        original = http_client.request.urlopen
        http_client.request.urlopen = router
        self.addCleanup(lambda: setattr(http_client.request, "urlopen", original))
        return RedmineHttpBackend(base_url="http://tracker.example/redmine", api_key="k")

    @staticmethod
    def _ctx() -> RequestContext:
        return RequestContext(actor="u", project="p", client="t", request_id="r", issue_project="97")

    def test_custom_status_no_stock_table_would_know(self) -> None:
        backend = self._backend()
        backend.update_status("12", "PENDING_REVIEW", None, self._ctx())
        self.assertEqual(self.put["issue"]["status_id"], 88)

    def test_unknown_status_names_what_this_instance_allows(self) -> None:
        backend = self._backend()
        with self.assertRaises(ValueError) as cm:
            backend.update_status("12", "TRIAGED", None, self._ctx())
        message = str(cm.exception)
        self.assertIn("TRIAGED", message)
        self.assertIn("PENDING_REVIEW", message)  # lists the instance's own vocabulary
        self.assertNotIn("REJECTED", message)     # ... and only that: stock-only names are absent

    def test_map_is_cached_then_refetched_once_on_a_miss(self) -> None:
        backend = self._backend()
        backend.update_status("12", "RESOLVED", None, self._ctx())
        backend.update_status("12", "NEW", None, self._ctx())
        self.assertEqual(len(self.fetches), 1)  # cached across calls
        # An admin adds a status while the process is up: the next call for it must
        # work without a restart, which is the whole reason for the refetch.
        self.rows = {"issue_statuses": self.rows["issue_statuses"] + [{"id": 101, "name": "Triaged"}]}
        backend.update_status("12", "TRIAGED", None, self._ctx())
        self.assertEqual(self.put["issue"]["status_id"], 101)
        self.assertEqual(len(self.fetches), 2)  # exactly one extra fetch, not one per call

    def test_search_filter_resolves_names_and_passes_through_open_closed(self) -> None:
        backend = self._backend()
        self.assertEqual(backend._status_filter("RESOLVED"), 42)
        self.assertEqual(backend._status_filter("open"), "open")
        self.assertEqual(backend._status_filter("*"), "*")
        with self.assertRaises(ValueError):
            backend._status_filter("nonsense")

    def test_a_cached_name_stops_being_trusted_after_the_ttl(self) -> None:
        # Adversarial review, 2026-08-10: a cache hit never re-validated, so after an
        # admin renamed a status the old name kept resolving to the old id -- and that
        # id now means something else, so a confirmed write landed in the wrong state.

        clock = [1000.0]
        import mcp_governance_gateway.issue_backend as issue_backend
        real_monotonic = issue_backend.time.monotonic
        issue_backend.time.monotonic = lambda: clock[0]  # type: ignore[assignment]
        self.addCleanup(lambda: setattr(issue_backend.time, "monotonic", real_monotonic))

        backend = self._backend()
        backend.update_status("12", "RESOLVED", None, self._ctx())
        self.assertEqual(self.put["issue"]["status_id"], 42)
        self.assertEqual(len(self.fetches), 1)

        # the instance is edited: RESOLVED is gone and 42 now means something else
        self.rows = {"issue_statuses": [{"id": 7, "name": "New"}, {"id": 42, "name": "Rejected"}]}
        clock[0] += issue_backend._ENUM_CACHE_TTL_SEC - 1
        backend.update_status("12", "RESOLVED", None, self._ctx())  # still cached, still wrong
        self.assertEqual(len(self.fetches), 1)

        clock[0] += 2  # past the TTL
        with self.assertRaises(ValueError) as cm:
            backend.update_status("12", "RESOLVED", None, self._ctx())
        self.assertIn("REJECTED", str(cm.exception))  # now rejected, naming what exists

    def test_an_unknown_search_filter_names_what_the_instance_offers(self) -> None:
        # The write path listed the vocabulary; the filter path did not.
        backend = self._backend()
        with self.assertRaises(ValueError) as cm:
            backend._status_filter("TRIAGED")
        message = str(cm.exception)
        self.assertIn("TRIAGED", message)
        self.assertIn("PENDING_REVIEW", message)   # this instance's own vocabulary
        self.assertIn("open", message)             # ... and the passthrough values

    def test_empty_status_list_fails_loud_rather_than_writing_nothing(self) -> None:
        backend = self._backend(rows={"issue_statuses": []})
        with self.assertRaises(IssueBackendError):
            backend.update_status("12", "RESOLVED", None, self._ctx())


# Trackers, priorities and categories as a customized instance reports them: none
# of these ids are what a stock Redmine seeds, so a test that expects them can only
# be reading them from the instance.
_TRACKER_ROWS = {"trackers": [{"id": 4, "name": "Task"}, {"id": 11, "name": "Bug"}]}
_PRIORITY_ROWS = {"issue_priorities": [
    {"id": 31, "name": "Low"}, {"id": 32, "name": "Normal"}, {"id": 33, "name": "High"},
]}
_CATEGORY_ROWS = {"issue_categories": [{"id": 61, "name": "Firmware"}, {"id": 62, "name": "Docs"}]}


class IssueWriteFieldTests(unittest.TestCase):
    """tracker / priority / dueDate / parentIssue / category on the Redmine backend."""

    def setUp(self) -> None:
        from mcp_governance_gateway import http_client

        self.fetches: list[str] = []
        self.writes: list[dict] = []
        self.other_project_issue = "555"

        def router(req, timeout):  # type: ignore[no-untyped-def]
            url, method = req.full_url, req.get_method()
            self.fetches.append(f"{method} {url}")
            if "/issue_statuses.json" in url:
                return FakeResponse(_STATUS_ROWS)
            if "/trackers.json" in url:
                return FakeResponse(_TRACKER_ROWS)
            if "/issue_priorities.json" in url:
                return FakeResponse(_PRIORITY_ROWS)
            if "/issue_categories.json" in url:
                return FakeResponse(_CATEGORY_ROWS)
            if "/projects/97.json" in url:
                return FakeResponse({"project": {"id": 97, "name": "Q"}})
            if f"/issues/{self.other_project_issue}.json" in url:
                # exists, but belongs to another tenant
                return FakeResponse({"issue": {"id": 555, "project": {"id": 55, "name": "Other"}}})
            if "/issues/12.json" in url and method == "GET":
                return FakeResponse({"issue": {
                    "id": 12, "project": {"id": 97}, "subject": "S", "description": "the body",
                    "status": {"name": "Resolved"}, "category": {"id": 61, "name": "Firmware"},
                }})
            if "/issues/900.json" in url and method == "GET":
                return FakeResponse({"issue": {"id": 900, "project": {"id": 97}}})
            if method in ("POST", "PUT"):
                self.writes.append(json.loads(req.data.decode("utf-8"))["issue"])
                return FakeResponse({"issue": {"id": 12, "project": {"id": 97}}})
            raise AssertionError((method, url))

        original = http_client.request.urlopen
        http_client.request.urlopen = router
        self.addCleanup(lambda: setattr(http_client.request, "urlopen", original))
        self.backend = RedmineHttpBackend(base_url="http://tracker.example", api_key="k")

    @staticmethod
    def _ctx() -> RequestContext:
        return RequestContext(actor="u", project="p", client="t", request_id="r", issue_project="97")

    def test_tracker_and_priority_resolve_by_name_not_by_a_stock_table(self) -> None:
        self.backend.create({"subject": "s", "tracker": "bug", "priority": "high"}, self._ctx())
        self.assertEqual(self.writes[-1]["tracker_id"], 11)
        self.assertEqual(self.writes[-1]["priority_id"], 33)

    def test_unknown_tracker_or_priority_lists_what_the_instance_has(self) -> None:
        for field, value, expected in [("tracker", "epic", "TASK"), ("priority", "blocker", "NORMAL")]:
            with self.subTest(field=field):
                with self.assertRaises(ValueError) as cm:
                    self.backend.create({"subject": "s", field: value}, self._ctx())
                self.assertIn(value, str(cm.exception))
                self.assertIn(expected, str(cm.exception))
                self.assertEqual(self.writes, [])

    def test_omitted_tracker_leaves_the_project_default_alone(self) -> None:
        # A stock Redmine has no "Task" tracker at all, so this must not invent one.
        self.backend.create({"subject": "s"}, self._ctx())
        self.assertNotIn("tracker_id", self.writes[-1])
        self.assertNotIn("priority_id", self.writes[-1])

    def test_due_date_must_be_a_real_calendar_date(self) -> None:
        self.backend.create({"subject": "s", "dueDate": "2026-08-31"}, self._ctx())
        self.assertEqual(self.writes[-1]["due_date"], "2026-08-31")
        for bad in ("31-08-2026", "2026-8-1", "2026-02-31"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.backend.create({"subject": "s", "dueDate": bad}, self._ctx())

    def test_start_date_is_forwarded_on_both_writes(self) -> None:
        self.backend.create({"subject": "s", "startDate": "2026-09-01"}, self._ctx())
        self.assertEqual(self.writes[-1]["start_date"], "2026-09-01")
        self.backend.update_status("12", "RESOLVED", 100, self._ctx(),
                                   planning={"startDate": "2026-09-02"})
        self.assertEqual(self.writes[-1]["start_date"], "2026-09-02")

    def test_planning_dates_report_the_invalid_field_without_writing(self) -> None:
        for field in ("startDate", "dueDate"):
            for bad in ("2026-9-01", "2026-02-31"):
                for operation in ("create", "update_status"):
                    with self.subTest(field=field, bad=bad, operation=operation):
                        with self.assertRaisesRegex(ValueError, field):
                            if operation == "create":
                                self.backend.create({"subject": "s", field: bad}, self._ctx())
                            else:
                                self.backend.update_status("12", "RESOLVED", 100, self._ctx(),
                                                           planning={field: bad})
                        self.assertEqual(self.writes, [])

    def test_read_shape_includes_nullable_planning_fields(self) -> None:
        from mcp_governance_gateway.issue_backend import _normalize_issue

        for priority, expected in (({"name": "HIGH"}, "high"), (None, None),
                                   ({"name": 42}, None)):
            with self.subTest(priority=priority):
                row = _normalize_issue({"priority": priority, "due_date": "2026-09-01", "start_date": "2026-08-20"})
                self.assertEqual(row["priority"], expected)
                self.assertEqual(row["dueDate"], "2026-09-01")
                self.assertEqual(row["startDate"], "2026-08-20")
        self.assertIsNone(_normalize_issue({})["startDate"])
        row = self.backend.get("12", self._ctx())
        self.assertIsNone(row["priority"])
        self.assertIsNone(row["dueDate"])

    def test_parent_issue_is_resolved_inside_this_project_only(self) -> None:
        self.backend.create({"subject": "s", "parentIssue": "900"}, self._ctx())
        self.assertEqual(self.writes[-1]["parent_issue_id"], 900)
        # a real issue in another project must 404 like a nonexistent one, and no
        # write may happen -- otherwise the field is an existence oracle
        self.writes.clear()
        with self.assertRaises(IssueBackendError) as cm:
            self.backend.create({"subject": "s", "parentIssue": self.other_project_issue}, self._ctx())
        self.assertEqual(cm.exception.status, 404)
        self.assertEqual(str(cm.exception), "issue not found")
        self.assertEqual(self.writes, [])

    def test_category_resolves_by_name_case_insensitively(self) -> None:
        self.backend.create({"subject": "s", "category": "firmware"}, self._ctx())
        self.assertEqual(self.writes[-1]["category_id"], 61)
        with self.assertRaises(ValueError) as cm:
            self.backend.create({"subject": "s", "category": "Bootloader"}, self._ctx())
        self.assertIn("Firmware", str(cm.exception))
        self.assertIn("Docs", str(cm.exception))

    def test_categories_are_read_live_because_members_can_edit_them(self) -> None:
        self.backend.categories(self._ctx())
        self.backend.categories(self._ctx())
        listings = [f for f in self.fetches if "issue_categories" in f]
        self.assertEqual(len(listings), 2)  # not cached, unlike the instance-global vocabularies

    def test_update_status_carries_assignee_and_planning(self) -> None:
        self.backend.update_status(
            "12", "RESOLVED", 100, self._ctx(),
            assignee="42", planning={"dueDate": "2026-09-01", "priority": "low"},
        )
        written = self.writes[-1]
        self.assertEqual(written["assigned_to_id"], "42")
        self.assertEqual(written["due_date"], "2026-09-01")
        self.assertEqual(written["priority_id"], 31)

    def test_description_is_on_get_only_not_on_list_shapes(self) -> None:
        self.assertEqual(self.backend.get("12", self._ctx())["description"], "the body")
        self.assertEqual(self.backend.get("12", self._ctx())["category"], "Firmware")
        created = self.backend.create({"subject": "s"}, self._ctx())
        self.assertNotIn("description", created)


class IssuesMineTests(unittest.TestCase):
    """issues.mine must never answer from the shared credential."""

    def _backend(self, resolver, enforce=False):
        return RedmineHttpBackend(
            base_url="http://tracker.example", api_key="SHARED",
            key_resolver=resolver, enforce_personal=enforce,
            credential_portal_url="https://gateway.example/admin",
        )

    @staticmethod
    def _ctx() -> RequestContext:
        return RequestContext(actor="u", project="p", client="t", request_id="r", issue_project="97")

    def test_no_key_store_fails_loud_with_where_to_go(self) -> None:
        with self.assertRaises(IssueBackendError) as cm:
            self._backend(None).mine(10, self._ctx())
        self.assertEqual(cm.exception.status, 428)
        self.assertTrue(str(cm.exception).endswith("https://gateway.example/admin"))

    def test_missing_key_fails_loud_even_in_optional_mode(self) -> None:
        # enforce_personal governs write attribution; this is a read whose entire
        # meaning is "mine", so the shared key is a wrong answer, not a degraded one.
        for enforce in (False, True):
            with self.subTest(enforce=enforce):
                with self.assertRaises(IssueBackendError) as cm:
                    self._backend(lambda actor: (KeyState.MISSING, None), enforce).mine(10, self._ctx())
                self.assertEqual(cm.exception.status, 428)

    def test_undecryptable_key_is_distinguished(self) -> None:
        with self.assertRaises(IssueBackendError) as cm:
            self._backend(lambda actor: (KeyState.UNDECRYPTABLE, None)).mine(10, self._ctx())
        self.assertEqual(cm.exception.status, 409)

    def test_present_key_reads_on_the_personal_key(self) -> None:
        from mcp_governance_gateway import http_client

        keys: list[str | None] = []

        def router(req, timeout):  # type: ignore[no-untyped-def]
            keys.append(req.headers.get("X-redmine-api-key"))
            if "/projects/97.json" in req.full_url:
                return FakeResponse({"project": {"id": 97, "name": "Q"}})
            return FakeResponse({"issues": [{"id": 7, "project": {"id": 97}}]})

        original = http_client.request.urlopen
        http_client.request.urlopen = router
        self.addCleanup(lambda: setattr(http_client.request, "urlopen", original))
        out = self._backend(lambda actor: (KeyState.OK, "PERSONAL")).mine(10, self._ctx())
        self.assertEqual(out["count"], 1)
        self.assertIn("PERSONAL", keys)          # the "me" read ran as the caller
        self.assertNotIn("PERSONAL", keys[:1])   # ... and project resolution did not


class PerCallerReadKeyTests(unittest.TestCase):
    """Reads run on the CALLER's key, not the shared service credential.

    Measured failure this pins: reads ran on the shared key, so the gateway's
    reach was the SERVICE ACCOUNT's project memberships. A member of a project
    the service account cannot see got a bare 403 on an issue their own account
    opens fine, and a non-member could read issues their own account could not.
    """

    def _backend(self, resolver, enforce=False):
        return RedmineHttpBackend(
            base_url="http://tracker.example", api_key="SHARED",
            key_resolver=resolver, enforce_personal=enforce,
            credential_portal_url="https://gateway.example/admin",
        )

    @staticmethod
    def _ctx() -> RequestContext:
        return RequestContext(actor="u", project="p", client="t", request_id="r", issue_project="97")

    def _router(self, keys):
        def router(req, timeout):  # type: ignore[no-untyped-def]
            keys.append(req.headers.get("X-redmine-api-key"))
            if "/projects/97.json" in req.full_url:
                return FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issue_statuses.json" in req.full_url:
                return FakeResponse({"issue_statuses": [{"id": 1, "name": "Open"}]})
            if "/issues.json" in req.full_url:
                return FakeResponse({"issues": [{"id": 7, "project": {"id": 97}}]})
            return FakeResponse({"issue": {"id": 7, "project": {"id": 97}, "subject": "s"}})
        return router

    def _patch(self, router):
        from mcp_governance_gateway import http_client
        original = http_client.request.urlopen
        http_client.request.urlopen = router
        self.addCleanup(lambda: setattr(http_client.request, "urlopen", original))

    def test_get_reads_on_the_callers_own_key(self) -> None:
        keys: list[str | None] = []
        self._patch(self._router(keys))
        self._backend(lambda actor: (KeyState.OK, "PERSONAL")).get("7", self._ctx())
        self.assertIn("PERSONAL", keys)

    def test_search_reads_on_the_callers_own_key(self) -> None:
        keys: list[str | None] = []
        self._patch(self._router(keys))
        self._backend(lambda actor: (KeyState.OK, "PERSONAL")).search({}, 10, self._ctx())
        self.assertIn("PERSONAL", keys)

    def test_unenrolled_callers_still_read_on_the_shared_key(self) -> None:
        # MISSING falls back deliberately: reads stay available to anyone who has
        # not enrolled, which is the whole reason enrolment is optional.
        keys: list[str | None] = []
        self._patch(self._router(keys))
        self._backend(lambda actor: (KeyState.MISSING, None)).get("7", self._ctx())
        self.assertEqual(set(keys), {"SHARED"})

    def test_a_degraded_keystore_fails_reads_closed_rather_than_answering_from_shared(self) -> None:
        # The defect this exists to prevent: a master-key outage reported as
        # MISSING silently reverted every ENROLLED caller's reads to the shared
        # credential's visibility -- a different answer, not a degraded one.
        keys: list[str | None] = []
        self._patch(self._router(keys))
        for op in (lambda b: b.get("7", self._ctx()), lambda b: b.search({}, 10, self._ctx())):
            with self.assertRaises(IssueBackendError) as cm:
                op(self._backend(lambda actor: (KeyState.DEGRADED, None)))
            self.assertEqual(cm.exception.status, 503)
        self.assertEqual(keys, [])  # never reached the tracker

    def test_an_undecryptable_key_fails_that_caller_only(self) -> None:
        with self.assertRaises(IssueBackendError) as cm:
            self._backend(lambda actor: (KeyState.UNDECRYPTABLE, None)).get("7", self._ctx())
        self.assertEqual(cm.exception.status, 409)


class WriteGatingReadKeyTests(unittest.TestCase):
    """The read that GATES a write runs on the key that will PERFORM the write.

    The read fix alone was half a fix: add_note resolved the caller's key, then
    verified the target on the SHARED key, so Redmine 403'd in front of the write
    for exactly the projects the read fix was meant to unblock.
    """

    def _backend(self, resolver):
        return RedmineHttpBackend(
            base_url="http://tracker.example", api_key="SHARED",
            key_resolver=resolver, credential_portal_url="https://gateway.example/admin",
        )

    @staticmethod
    def _ctx() -> RequestContext:
        return RequestContext(actor="u", project="p", client="t", request_id="r", issue_project="97")

    def _verify_key_for(self, op):
        """Return the key used by the GET that verifies the target, per operation."""
        from mcp_governance_gateway import http_client
        seen: list[tuple[str, str | None]] = []

        def router(req, timeout):  # type: ignore[no-untyped-def]
            method = req.get_method()
            seen.append((req.full_url, req.headers.get("X-redmine-api-key")))
            if "/projects/97.json" in req.full_url:
                return FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issue_statuses.json" in req.full_url:
                return FakeResponse({"issue_statuses": [{"id": 1, "name": "OPEN"}]})
            if method == "GET":
                return FakeResponse({"issue": {"id": 7, "project": {"id": 97}, "subject": "s"}})
            return FakeResponse({"issue": {"id": 7, "project": {"id": 97}}})

        original = http_client.request.urlopen
        http_client.request.urlopen = router
        self.addCleanup(lambda: setattr(http_client.request, "urlopen", original))
        op(self._backend(lambda actor: (KeyState.OK, "PERSONAL")))
        # the verification GET on the issue itself, not project resolution
        return [k for url, k in seen if "/issues/7.json" in url]

    def test_add_note_verifies_the_target_on_the_writers_key(self) -> None:
        keys = self._verify_key_for(lambda b: b.add_note("7", "n", self._ctx()))
        self.assertTrue(keys)
        self.assertNotIn("SHARED", keys)
        self.assertIn("PERSONAL", keys)

    def test_update_status_verifies_the_target_on_the_writers_key(self) -> None:
        keys = self._verify_key_for(
            lambda b: b.update_status("7", "open", None, self._ctx())
        )
        self.assertTrue(keys)
        self.assertNotIn("SHARED", keys)
        self.assertIn("PERSONAL", keys)


class CredentialPortalHintTests(unittest.TestCase):
    """The enrollment errors may point at the deployment's portal, and must not
    invent a host when none is configured."""

    def _backend(self, portal):
        return RedmineHttpBackend(
            base_url="http://tracker.example",
            api_key=None,
            key_resolver=lambda actor: (KeyState.MISSING, None),
            enforce_personal=True,
            credential_portal_url=portal,
        )

    def _message(self, portal):
        with self.assertRaises(IssueBackendError) as cm:
            self._backend(portal).add_note("1", "hi", RequestContext(
                actor="u", project="p", client="t", request_id="r", issue_project="97"))
        return str(cm.exception)

    def test_no_url_when_unconfigured(self) -> None:
        message = self._message(None)
        self.assertIn("credential-enrollment endpoint", message)
        self.assertNotIn("http", message)
        self.assertNotIn("->", message)

    def test_url_appended_when_configured(self) -> None:
        self.assertTrue(
            self._message("https://gateway.example/admin/credentials").endswith(
                " -> https://gateway.example/admin/credentials"
            )
        )

    def test_trailing_slash_is_not_doubled(self) -> None:
        self.assertTrue(self._message("https://gateway.example/admin/").endswith("/admin"))


class IssuePlanningFieldGateTests(unittest.TestCase):
    """The gateway side of the new write fields: passed through, and bound to the
    confirmation so they cannot be swapped between prepare and commit."""

    def setUp(self) -> None:
        self.issues = FakeIssueBackend()
        self.app = GatewayApp(
            memory_backend=FakeMemoryBackend(), audit_sink=ListAuditSink(),
            issue_backend=self.issues, confirmation=ConfirmationStore(),
        )
        self.principal = Principal(
            actor="u", project="proj", roles=("issue_writer",), token_id="t", issue_project="97",
        )
        self.reader = Principal(actor="r", project="proj", roles=(), token_id="t2", issue_project="97")

    def _call(self, name, arguments, principal=None):
        response = self.app.handle_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}},
            principal or self.principal,
        )
        assert response is not None
        return response

    def _commit(self, name, arguments):
        first = self._call(name, arguments)["result"]["structuredContent"]
        return self._call(name, {**arguments, "confirm": first["confirmationId"]})

    def test_planning_fields_reach_the_backend(self) -> None:
        self._commit("issues.create", {
            "subject": "s", "tracker": "bug", "assignee": "42",
            "dueDate": "2026-09-01", "priority": "high", "parentIssue": 900, "category": "Firmware",
        })
        fields = self.issues.calls[-1][1]
        self.assertEqual(fields["tracker"], "bug")
        self.assertEqual(fields["assignee"], "42")
        self.assertEqual(fields["dueDate"], "2026-09-01")
        self.assertEqual(fields["priority"], "high")
        self.assertEqual(fields["parentIssue"], "900")
        self.assertEqual(fields["category"], "Firmware")

    def test_a_planning_field_swapped_after_confirm_does_not_commit(self) -> None:
        # Without the planning fields in the confirmation binding, a caller could
        # confirm one due date and commit another.
        first = self._call("issues.create", {"subject": "s", "dueDate": "2026-09-01"})["result"]["structuredContent"]
        out = self._call("issues.create", {
            "subject": "s", "dueDate": "2026-12-25", "confirm": first["confirmationId"],
        })["result"]["structuredContent"]
        self.assertIn("dueDate", out["confirmError"])
        self.assertEqual(self.issues.calls, [])

    def test_adding_a_planning_field_after_confirm_does_not_commit(self) -> None:
        first = self._call("issues.create", {"subject": "s"})["result"]["structuredContent"]
        out = self._call("issues.create", {
            "subject": "s", "parentIssue": 900, "confirm": first["confirmationId"],
        })["result"]["structuredContent"]
        self.assertIn("parentIssue", out["confirmError"])
        self.assertEqual(self.issues.calls, [])

    def test_update_status_forwards_assignee_and_planning(self) -> None:
        self._commit("issues.update_status", {
            "id": 12, "status": "RESOLVED", "assignee": "42", "priority": "low",
        })
        _, issue_id, status, done_ratio, assignee, planning = self.issues.calls[-1]
        self.assertEqual((issue_id, status, assignee), ("12", "RESOLVED", "42"))
        self.assertEqual(planning, {"priority": "low"})

    def test_mine_and_categories_are_reads_not_gated_writes(self) -> None:
        for name in ("issues.mine", "issues.categories"):
            with self.subTest(name=name):
                out = self._call(name, {}, self.reader)["result"]["structuredContent"]
                self.assertNotIn("confirmationRequired", out)  # a read needs no confirmation
        # ... and a reader without issue_writer reached both
        self.assertEqual([c[0] for c in self.issues.calls], ["mine", "categories"])

    def test_writes_still_need_the_writer_role(self) -> None:
        denied = self._call("issues.create", {"subject": "s"}, self.reader)
        self.assertEqual(denied["error"]["code"], -32003)
        self.assertEqual(self.issues.calls, [])
