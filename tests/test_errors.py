"""One exception shape across the adapters, and the error boundary that relies on it."""
import unittest

from mcp_governance_gateway.audit import ListAuditSink
from mcp_governance_gateway.auth import Principal
from mcp_governance_gateway.ci_backend import CiBackendError
from mcp_governance_gateway.docs_assets import AssetStageError
from mcp_governance_gateway.docs_backend import DocsBackendError
from mcp_governance_gateway.errors import BackendError
from mcp_governance_gateway.issue_backend import IssueBackendError
from mcp_governance_gateway.mcp import GatewayApp
from mcp_governance_gateway.memory_backend import MemoryBackend, MemoryBackendError
from mcp_governance_gateway.review_backend import ReviewBackendError


class HierarchyTests(unittest.TestCase):
    def test_every_adapter_error_is_a_backend_error_with_a_status(self):
        for cls in (MemoryBackendError, IssueBackendError, DocsBackendError, CiBackendError, ReviewBackendError):
            with self.subTest(cls=cls.__name__):
                exc = cls("boom", status=503)
                self.assertIsInstance(exc, BackendError)
                self.assertEqual((str(exc), exc.status), ("boom", 503))
                self.assertIsNone(cls("bare").status)

    def test_an_asset_stage_error_keeps_its_400_default(self):
        self.assertEqual(AssetStageError("bad").status, 400)
        self.assertIsInstance(AssetStageError("bad"), BackendError)

    def test_ci_and_review_errors_are_no_longer_the_tracker_error(self):
        # Both used to be `IssueBackendError` under another name, so an isinstance
        # check could not tell a CI failure from a tracker one.
        self.assertNotIsInstance(CiBackendError("x"), IssueBackendError)
        self.assertNotIsInstance(ReviewBackendError("x"), IssueBackendError)
        self.assertNotIsInstance(CiBackendError("x"), ReviewBackendError)


class _NullMemory(MemoryBackend):
    pass


class ErrorBoundaryTests(unittest.TestCase):
    def test_ci_not_enabled_is_a_ci_error_and_a_tool_error(self):
        # It was raised as a DocsBackendError; the client saw the same message,
        # but the class named the wrong backend to anyone catching by type.
        from mcp_governance_gateway.tools import ci
        app = GatewayApp(memory_backend=_NullMemory(), audit_sink=ListAuditSink())
        principal = Principal(actor="1", project="p", roles=(), token_id="t")
        with self.assertRaises(CiBackendError) as caught:
            ci.call(app, "ci.status", {}, principal, None)
        self.assertEqual(caught.exception.status, 404)
        response = app.handle_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "ci.status", "arguments": {}}},
            principal,
        )
        self.assertTrue(response["result"]["isError"])
        self.assertIn("CI is not enabled", response["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
