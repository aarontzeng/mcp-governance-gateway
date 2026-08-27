from __future__ import annotations

import unittest

from mcp_governance_gateway.memory_backend import HttpMemoryBackend, RequestContext


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


if __name__ == "__main__":
    unittest.main()
