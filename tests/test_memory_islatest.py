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
