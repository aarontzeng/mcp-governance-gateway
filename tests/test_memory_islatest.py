from __future__ import annotations

import unittest

from mcp_governance_gateway.memory_backend import HttpMemoryBackend, MemoryBackendError, RequestContext


class ListSupersededTests(unittest.TestCase):
    def _backend(self, memories):
        b = HttpMemoryBackend(base_url="http://x", backend_token=None, search_path="/s", save_path="/r")
        # stub the paged fetch: return the fixture on the first page, empty after
        b._get = lambda path, params: ({"memories": memories} if params.get("offset", 0) == 0 else {"memories": []})
        return b

    def test_list_drops_superseded_keeps_latest_and_unflagged(self):
        b = self._backend([
            {"id": "v1", "project": "p", "content": "cache ttl", "isLatest": False, "updatedAt": "2026-01-01"},
            {"id": "v2", "project": "p", "content": "cache ttl", "isLatest": True, "updatedAt": "2026-01-02"},
            {"id": "old", "project": "p", "content": "no-flag legacy record"},  # missing isLatest -> kept
            {"id": "other", "project": "q", "content": "other project", "isLatest": True},
        ])
        ctx = RequestContext(actor="10000001", project="p", client="t", request_id="r")
        out = b.list(50, 0, ctx)
        ids = [m["id"] for m in out["memories"]]
        self.assertNotIn("v1", ids)  # superseded version dropped
        self.assertIn("v2", ids)  # current version kept
        self.assertIn("old", ids)  # record without the flag is kept (don't over-drop)
        self.assertNotIn("other", ids)  # other project still excluded
        self.assertEqual(out["total"], 2)


class ProjectListWindowTests(unittest.TestCase):
    def _backend(self, kind, rows):
        b = HttpMemoryBackend(base_url="http://x", backend_token=None, search_path="/s", save_path="/r")
        # Model the backend's default page, before gateway sorting/filtering.
        b._get = lambda path, params: {kind: rows[:params.get("limit", 50)]}
        return b

    def _ctx(self):
        return RequestContext(actor="alice", project="p", client="t", request_id="r")

    def test_lessons_beyond_backend_default_compete_before_gateway_limit(self):
        rows = [{"id": str(i), "project": "p", "confidence": 0.1,
                 "tags": ["actor:alice"]} for i in range(50)]
        rows.append({"id": "strong", "project": "p", "confidence": 0.9,
                     "tags": ["actor:bob"]})
        out = self._backend("lessons", rows).lesson_list(1, self._ctx())
        self.assertEqual([r["id"] for r in out["lessons"]], ["strong"])
        self.assertEqual(out["lessons"][0]["actor"], "bob")
        self.assertEqual(out["total"], 51)
        self.assertFalse(out["truncated"])

    def test_open_actions_beyond_backend_default_survive_done_filter(self):
        rows = [{"id": str(i), "project": "p", "status": "done",
                 "tags": ["actor:alice"]} for i in range(50)]
        rows.append({"id": "open", "project": "p", "status": "pending",
                     "tags": ["actor:bob"]})
        out = self._backend("actions", rows).action_list(1, self._ctx())
        self.assertEqual([r["id"] for r in out["actions"]], ["open"])
        self.assertEqual(out["actions"][0]["actor"], "bob")
        self.assertEqual(out["total"], 1)
        self.assertFalse(out["truncated"])
        self.assertEqual(self._backend("actions", rows).action_list(
            1, self._ctx(), include_done=True)["total"], 51)

    def test_full_fetch_window_is_marked_truncated_before_project_filter(self):
        for kind, method in (("lessons", "lesson_list"), ("actions", "action_list")):
            with self.subTest(kind=kind):
                rows = [{"id": str(i), "project": "other"} for i in range(5001)]
                out = getattr(self._backend(kind, rows), method)(1, self._ctx())
                self.assertEqual(out["count"], 0)
                self.assertEqual(out["total"], 0)
                self.assertTrue(out["truncated"])

    def test_total_counts_project_matches_before_page_limit(self):
        for kind, method in (("lessons", "lesson_list"), ("actions", "action_list")):
            with self.subTest(kind=kind):
                rows = [{"id": "foreign", "project": "other"},
                        {"id": "first", "project": "p"},
                        {"id": "second", "project": "p"}]
                out = getattr(self._backend(kind, rows), method)(1, self._ctx())
                self.assertEqual(out["count"], 1)
                self.assertEqual(out["total"], 2)
                self.assertFalse(out["truncated"])


class ActionUpdateProjectCheckTests(unittest.TestCase):
    """`action_update_status` trusts neither the listing filter nor the update
    endpoint: the target row must carry the caller's project on the way in, and
    the updated row must still carry it on the way out."""

    def _backend(self, listed, updated):
        b = HttpMemoryBackend(base_url="http://x", backend_token=None, search_path="/s", save_path="/r")
        b.posted = []
        b._get = lambda path, params: {"actions": listed}
        b._post = lambda path, body: (b.posted.append((path, body)) or {"action": updated})
        return b

    def test_a_listing_that_ignores_the_project_filter_does_not_unlock_another_projects_action(self):
        # Simulates a backend whose /actions endpoint returns rows regardless of
        # the `project` query parameter: the row is present, but it is not ours.
        b = self._backend(
            listed=[{"id": "act_9", "project": "other", "status": "open"}],
            updated={"id": "act_9", "project": "other", "status": "done"},
        )
        ctx = RequestContext(actor="10000001", project="p", client="t", request_id="r")
        with self.assertRaises(MemoryBackendError) as cm:
            b.action_update_status("act_9", "done", ctx)
        self.assertEqual(cm.exception.status, 404)
        self.assertEqual(b.posted, [])  # refused before any write reached the backend

    def test_the_lookup_asks_for_the_whole_project_window_not_the_default_page(self):
        # An action beyond the backend's default page is still this project's;
        # the pre-update lookup must fetch the same bounded window the listing does.
        b = self._backend(listed=[{"id": "act_9", "project": "p", "status": "open"}],
                          updated={"id": "act_9", "project": "p", "status": "done"})
        seen = []
        b._get = lambda path, params: (seen.append(params) or {"actions": [{"id": "act_9", "project": "p", "status": "open"}]})
        ctx = RequestContext(actor="10000001", project="p", client="t", request_id="r")
        b.action_update_status("act_9", "done", ctx)
        self.assertEqual(seen, [{"project": "p", "limit": 5000}])

    def test_the_callers_own_action_is_updated(self):
        b = self._backend(
            listed=[{"id": "act_1", "project": "p", "status": "open"}],
            updated={"id": "act_1", "project": "p", "status": "done"},
        )
        ctx = RequestContext(actor="10000001", project="p", client="t", request_id="r")
        out = b.action_update_status("act_1", "done", ctx)
        self.assertEqual(out, {"updated": True, "id": "act_1", "status": "done"})
        self.assertEqual(len(b.posted), 1)


if __name__ == "__main__":
    unittest.main()
