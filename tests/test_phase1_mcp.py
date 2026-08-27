from __future__ import annotations

from pathlib import Path
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcp_governance_gateway.audit import ListAuditSink
from mcp_governance_gateway.auth import AuthError, BearerTokenAuthenticator, IdentityVerifier, Principal
from mcp_governance_gateway.config import Settings
from mcp_governance_gateway.limits import InMemoryMemoryWriteLimiter, MemoryLimitConfig
from mcp_governance_gateway.confirm import ConfirmationStore
from mcp_governance_gateway.issue_backend import IssueBackend, IssueBackendError, RedmineHttpBackend
from mcp_governance_gateway.mcp import GatewayApp, tool_definitions
from mcp_governance_gateway.memory_backend import HttpMemoryBackend, MemoryBackend, RequestContext
from mcp_governance_gateway.redmine_keystore import KeyState
from mcp_governance_gateway.server import _is_loopback_host, build_server, is_origin_allowed


class FakeMemoryBackend(MemoryBackend):
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def search(self, query: str, limit: int, context: RequestContext) -> dict[str, object]:
        self.calls.append({"tool": "search", "query": query, "limit": limit, **context.metadata()})
        return {"results": [{"observation": {"id": "obs_1"}}], "count": 1}

    def save(self, text: str, tags: list[str], context: RequestContext) -> dict[str, object]:
        self.calls.append({"tool": "save", "text": text, "tags": tags, **context.metadata()})
        return {"saved": True, "project": context.project, "id": "mem_1"}

    def list(self, limit: int, offset: int, context: RequestContext) -> dict[str, object]:
        self.calls.append({"tool": "list", "limit": limit, "offset": offset, **context.metadata()})
        return {
            "memories": [{"id": "mem_1", "project": context.project, "title": "t"}],
            "count": 1,
            "total": 1,
            "offset": offset,
            "truncated": False,
        }

    def lesson_save(self, rule: str, reason, confidence: float, context: RequestContext) -> dict[str, object]:
        self.calls.append({"tool": "lesson_save", "rule": rule, "reason": reason, "confidence": confidence, **context.metadata()})
        return {"saved": True, "project": context.project, "id": "lsn_1"}

    def lesson_list(self, limit: int, context: RequestContext) -> dict[str, object]:
        self.calls.append({"tool": "lesson_list", "limit": limit, **context.metadata()})
        return {"lessons": [{"id": "lsn_1", "project": context.project, "content": "c", "confidence": 0.9}], "count": 1}

    def action_create(self, title: str, description, priority, context: RequestContext) -> dict[str, object]:
        self.calls.append({"tool": "action_create", "title": title, "description": description, "priority": priority, **context.metadata()})
        return {"created": True, "project": context.project, "id": "act_1", "status": "pending"}

    def action_list(self, limit: int, context: RequestContext, include_done: bool = False) -> dict[str, object]:
        self.calls.append({"tool": "action_list", "limit": limit, "include_done": include_done, **context.metadata()})
        return {"actions": [{"id": "act_1", "project": context.project, "title": "t", "status": "pending"}], "count": 1}

    def action_update_status(self, action_id: str, status: str, context: RequestContext) -> dict[str, object]:
        self.calls.append({"tool": "action_update_status", "action_id": action_id, "status": status, **context.metadata()})
        return {"updated": True, "id": action_id, "status": status}


class FakeIssueBackend(IssueBackend):
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def get(self, issue_id, context):  # type: ignore[no-untyped-def]
        self.calls.append(("get", issue_id, context.redmine_project))
        return {"id": issue_id, "projectId": context.redmine_project, "subject": "x"}

    def search(self, filters, limit, context):  # type: ignore[no-untyped-def]
        self.calls.append(("search", filters, limit, context.redmine_project))
        return {"issues": [{"id": "1"}], "count": 1}

    def create(self, fields, context):  # type: ignore[no-untyped-def]
        self.calls.append(("create", fields, context.redmine_project))
        return {"created": True, "id": "99", "subject": fields["subject"]}

    def add_note(self, issue_id, note, context):  # type: ignore[no-untyped-def]
        self.calls.append(("add_note", issue_id, note))
        return {"noted": True, "id": issue_id}

    def update_status(self, issue_id, status, done_ratio, context, *, assignee=None, planning=None):  # type: ignore[no-untyped-def]
        self.calls.append(("update_status", issue_id, status, done_ratio, assignee, planning or {}))
        return {"updated": True, "id": issue_id, "status": status}

    def mine(self, limit, context):  # type: ignore[no-untyped-def]
        self.calls.append(("mine", limit, context.redmine_project))
        return {"issues": [{"id": "7"}], "count": 1}

    def categories(self, context):  # type: ignore[no-untyped-def]
        self.calls.append(("categories", context.redmine_project))
        return {"categories": [{"id": "3", "name": "Firmware"}], "count": 1}


class GatewayAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = FakeMemoryBackend()
        self.audit = ListAuditSink()
        self.app = GatewayApp(memory_backend=self.backend, audit_sink=self.audit)
        self.principal = Principal(
            actor="user@example.com",
            project="example-project",
            roles=("developer",),
            token_id="tok_1",
        )

    def test_initialize_advertises_tool_capability(self) -> None:
        response = self.app.handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test"}},
            },
            self.principal,
        )

        assert response is not None
        self.assertEqual(response["result"]["protocolVersion"], "2025-06-18")
        self.assertIn("tools", response["result"]["capabilities"])

    def test_tools_list_returns_phase1_memory_tools(self) -> None:
        response = self.app.handle_rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, self.principal)

        assert response is not None
        tool_names = [tool["name"] for tool in response["result"]["tools"]]
        # this app has no issue backend and the principal carries no redmine_project,
        # so tools/list advertises only the memory tools
        self.assertEqual(tool_names, ["memory.search", "memory.save", "memory.list", "memory.lesson_save", "memory.lesson_list", "memory.action_create", "memory.action_list", "memory.action_update_status"])

    def test_memory_save_injects_gateway_metadata_and_audits(self) -> None:
        response = self.app.handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "memory.save", "arguments": {"text": "remember this", "tags": ["phase1"]}},
            },
            self.principal,
        )

        assert response is not None
        self.assertEqual(response["result"]["structuredContent"]["project"], "example-project")
        self.assertEqual(self.backend.calls[0]["projectId"], "example-project")
        self.assertEqual(self.backend.calls[0]["actor"], "user@example.com")
        self.assertEqual(self.backend.calls[0]["source"], "mcp-governance-gateway")
        self.assertIn("requestId", self.backend.calls[0])
        self.assertEqual(self.audit.events[0].tool, "memory.save")
        self.assertEqual(self.audit.events[0].decision, "allow")
        self.assertEqual(self.audit.events[0].outcome, "ok")
        self.assertEqual(self.audit.events[0].resource_id, "mem_1")
        self.assertEqual(self.audit.events[0].backend_status, "ok")
        self.assertIsNotNone(self.audit.events[0].duration_ms)

    def test_memory_list_dispatches_and_audits(self) -> None:
        response = self.app.handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {"name": "memory.list", "arguments": {"limit": 5}},
            },
            self.principal,
        )
        assert response is not None
        self.assertEqual(response["result"]["structuredContent"]["count"], 1)
        self.assertEqual(self.backend.calls[-1]["tool"], "list")
        self.assertEqual(self.audit.events[-1].tool, "memory.list")
        self.assertEqual(self.audit.events[-1].outcome, "ok")

    def test_lesson_save_and_list_dispatch_and_audit(self) -> None:
        save = self.app.handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 20,
                "method": "tools/call",
                "params": {"name": "memory.lesson_save", "arguments": {"rule": "always lint before commit", "reason": "CI blocks otherwise", "confidence": 0.9}},
            },
            self.principal,
        )
        assert save is not None
        self.assertEqual(save["result"]["structuredContent"], {"saved": True, "project": self.principal.project, "id": "lsn_1"})
        self.assertEqual(self.backend.calls[-1]["tool"], "lesson_save")
        self.assertEqual(self.backend.calls[-1]["confidence"], 0.9)
        self.assertEqual(self.audit.events[-1].tool, "memory.lesson_save")

        listed = self.app.handle_rpc(
            {"jsonrpc": "2.0", "id": 21, "method": "tools/call", "params": {"name": "memory.lesson_list", "arguments": {"limit": 5}}},
            self.principal,
        )
        assert listed is not None
        self.assertEqual(listed["result"]["structuredContent"]["count"], 1)
        self.assertEqual(self.backend.calls[-1]["tool"], "lesson_list")
        self.assertEqual(self.audit.events[-1].tool, "memory.lesson_list")

    def test_action_create_and_list_dispatch_and_audit(self) -> None:
        created = self.app.handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 22,
                "method": "tools/call",
                "params": {"name": "memory.action_create", "arguments": {"title": "revisit token rotation", "description": "after debug", "priority": "high"}},
            },
            self.principal,
        )
        assert created is not None
        self.assertEqual(created["result"]["structuredContent"]["created"], True)
        self.assertEqual(created["result"]["structuredContent"]["project"], self.principal.project)
        self.assertEqual(self.backend.calls[-1]["tool"], "action_create")
        self.assertEqual(self.audit.events[-1].tool, "memory.action_create")

        listed = self.app.handle_rpc(
            {"jsonrpc": "2.0", "id": 23, "method": "tools/call", "params": {"name": "memory.action_list", "arguments": {}}},
            self.principal,
        )
        assert listed is not None
        self.assertEqual(listed["result"]["structuredContent"]["count"], 1)
        self.assertEqual(self.backend.calls[-1]["tool"], "action_list")
        self.assertEqual(self.audit.events[-1].tool, "memory.action_list")

    def test_action_update_status_dispatch_and_enum_validation(self) -> None:
        ok = self.app.handle_rpc(
            {"jsonrpc": "2.0", "id": 24, "method": "tools/call",
             "params": {"name": "memory.action_update_status", "arguments": {"action_id": "act_1", "status": "done"}}},
            self.principal,
        )
        assert ok is not None
        self.assertEqual(ok["result"]["structuredContent"], {"updated": True, "id": "act_1", "status": "done"})
        self.assertEqual(self.backend.calls[-1]["tool"], "action_update_status")
        self.assertEqual(self.audit.events[-1].tool, "memory.action_update_status")
        # invalid status is rejected server-side BEFORE the backend is touched
        n = len(self.backend.calls)
        bad = self.app.handle_rpc(
            {"jsonrpc": "2.0", "id": 25, "method": "tools/call",
             "params": {"name": "memory.action_update_status", "arguments": {"action_id": "act_1", "status": "pending"}}},
            self.principal,
        )
        assert bad is not None
        self.assertIn("error", bad)
        self.assertEqual(len(self.backend.calls), n)  # not forwarded to the backend

    def test_disallowed_tool_fails_closed(self) -> None:
        response = self.app.handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "memory.delete", "arguments": {"id": "mem_1"}},
            },
            self.principal,
        )

        assert response is not None
        self.assertEqual(response["error"]["code"], -32003)
        self.assertEqual(self.backend.calls, [])
        self.assertEqual(self.audit.events[0].tool, "memory.delete")
        self.assertEqual(self.audit.events[0].decision, "deny")
        self.assertEqual(self.audit.events[0].outcome, "denied")

    def test_memory_save_rejects_text_over_configured_byte_limit(self) -> None:
        app = GatewayApp(
            memory_backend=self.backend,
            audit_sink=self.audit,
            memory_write_limiter=InMemoryMemoryWriteLimiter(
                MemoryLimitConfig(max_save_text_bytes=4, user_writes_per_minute=0, project_writes_per_day=0)
            ),
        )

        response = app.handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "memory.save", "arguments": {"text": "too long"}},
            },
            self.principal,
        )

        assert response is not None
        self.assertEqual(response["error"]["code"], -32003)
        self.assertIn("memory.save text exceeds", response["error"]["message"])
        self.assertEqual(self.backend.calls, [])
        self.assertEqual(self.audit.events[0].tool, "memory.save")
        self.assertEqual(self.audit.events[0].decision, "deny")
        self.assertEqual(self.audit.events[0].outcome, "denied")

    def test_memory_save_enforces_per_user_minute_quota(self) -> None:
        limiter = InMemoryMemoryWriteLimiter(
            MemoryLimitConfig(max_save_text_bytes=100, user_writes_per_minute=1, project_writes_per_day=0),
            clock=lambda: 1000.0,
        )
        app = GatewayApp(memory_backend=self.backend, audit_sink=self.audit, memory_write_limiter=limiter)

        first = app.handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "memory.save", "arguments": {"text": "first"}},
            },
            self.principal,
        )
        second = app.handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "memory.save", "arguments": {"text": "second"}},
            },
            self.principal,
        )

        assert first is not None
        assert second is not None
        self.assertIn("structuredContent", first["result"])
        self.assertEqual(second["error"]["code"], -32003)
        self.assertIn("per-user write rate", second["error"]["message"])
        self.assertEqual(len(self.backend.calls), 1)
        self.assertEqual(self.audit.events[-1].decision, "deny")

    def test_memory_save_enforces_per_project_daily_quota(self) -> None:
        limiter = InMemoryMemoryWriteLimiter(
            MemoryLimitConfig(max_save_text_bytes=100, user_writes_per_minute=0, project_writes_per_day=1),
            clock=lambda: 1000.0,
        )
        app = GatewayApp(memory_backend=self.backend, audit_sink=self.audit, memory_write_limiter=limiter)

        first = app.handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {"name": "memory.save", "arguments": {"text": "first"}},
            },
            self.principal,
        )
        second = app.handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": "memory.save", "arguments": {"text": "second"}},
            },
            self.principal,
        )

        assert first is not None
        assert second is not None
        self.assertIn("structuredContent", first["result"])
        self.assertEqual(second["error"]["code"], -32003)
        self.assertIn("per-project daily write quota", second["error"]["message"])
        self.assertEqual(len(self.backend.calls), 1)
        self.assertEqual(self.audit.events[-1].decision, "deny")

    def test_read_rate_limit_denies_and_audits(self) -> None:
        limiter = InMemoryMemoryWriteLimiter(
            MemoryLimitConfig(user_writes_per_minute=0, project_writes_per_day=0, user_reads_per_minute=1),
            clock=lambda: 1000.0,
        )
        app = GatewayApp(memory_backend=self.backend, audit_sink=self.audit, memory_write_limiter=limiter)

        first = app.handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {"name": "memory.search", "arguments": {"query": "a"}},
            },
            self.principal,
        )
        second = app.handle_rpc(
            {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {"name": "memory.search", "arguments": {"query": "b"}},
            },
            self.principal,
        )

        assert first is not None
        assert second is not None
        self.assertIn("result", first)
        self.assertEqual(second["error"]["code"], -32003)
        self.assertIn("per-user read rate", second["error"]["message"])
        self.assertEqual(len(self.backend.calls), 1)
        self.assertEqual(self.audit.events[-1].decision, "deny")

    def test_project_daily_quota_resets_next_day_and_bucket_stays_bounded(self) -> None:
        clock = {"now": 1000.0}
        limiter = InMemoryMemoryWriteLimiter(
            MemoryLimitConfig(max_save_text_bytes=100, user_writes_per_minute=0, project_writes_per_day=1),
            clock=lambda: clock["now"],
        )
        self.assertTrue(limiter.check_and_record(self.principal, "a").allowed)
        self.assertFalse(limiter.check_and_record(self.principal, "b").allowed)

        clock["now"] += 86_400  # next day
        self.assertTrue(limiter.check_and_record(self.principal, "c").allowed)
        # keyed by project only, so the bucket does not grow one entry per day
        self.assertEqual(len(limiter._project_day_writes), 1)


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

        with self.assertRaises(Exception):
            authenticator.authenticate_header(None)
        with self.assertRaises(Exception):
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


class SettingsTests(unittest.TestCase):
    def test_loads_memory_limit_settings_from_environment(self) -> None:
        with mock.patch.dict(
            "os.environ",
            {
                "GATEWAY_TOKEN_FILE": "/tmp/tokens.json",
                "MEMORY_SAVE_MAX_TEXT_BYTES": "4096",
                "MEMORY_USER_WRITES_PER_MINUTE": "7",
                "MEMORY_PROJECT_WRITES_PER_DAY": "99",
            },
            clear=True,
        ):
            settings = Settings.from_env()

        self.assertEqual(settings.memory_save_max_text_bytes, 4096)
        self.assertEqual(settings.memory_user_writes_per_minute, 7)
        self.assertEqual(settings.memory_project_writes_per_day, 99)

    def test_negative_memory_limit_is_rejected(self) -> None:
        with mock.patch.dict(
            "os.environ",
            {"GATEWAY_TOKEN_FILE": "/tmp/tokens.json", "MEMORY_USER_WRITES_PER_MINUTE": "-1"},
            clear=True,
        ):
            with self.assertRaises(ValueError):
                Settings.from_env()


class HttpMemoryBackendTests(unittest.TestCase):
    def test_search_passes_project_and_strips_aggregate_fields(self) -> None:
        captured: dict[str, object] = {}

        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return _FakeResponse(
                {
                    "format": "v1",
                    "results": [
                        {
                            "observation": {
                                "id": "obs_1",
                                "project": "example-project",
                                "title": "Tenancy is server-side",
                                "narrative": "The project claim never comes from the client.",
                                "concepts": ["actor:10000001"],
                                "timestamp": "2026-07-10T00:00:00Z",
                            },
                            "score": 0.9,
                        },
                        {"observation": {"id": "obs_2"}, "score": 0.7},
                    ],
                    "tokens_used": 1000,
                    "truncated": True,
                }
            )

        import mcp_governance_gateway.memory_backend as memory_backend

        original = memory_backend.request.urlopen
        memory_backend.request.urlopen = fake_urlopen
        try:
            backend = HttpMemoryBackend(
                base_url="http://memory.internal:3111", backend_token=None,
                search_path="/agentmemory/search", save_path="/agentmemory/remember",
            )
            result = backend.search(
                "tenant isolation", 10,
                RequestContext(actor="u", project="example-project", client="t", request_id="r"),
            )
        finally:
            memory_backend.request.urlopen = original

        # gateway injects the token's project; agentmemory filters server-side
        self.assertEqual(captured["body"], {"query": "tenant isolation", "limit": 10, "project": "example-project"})
        # Each hit arrives wrapped as {observation, score}: the wrapper is unwrapped
        # to the documented flat schema, so `content` carries the text instead of
        # being empty while the real fields sit one level down untouched.
        self.assertEqual(result["count"], 2)
        first = result["results"][0]
        self.assertEqual(first["id"], "obs_1")
        self.assertEqual(first["content"], "The project claim never comes from the client.")
        self.assertEqual(first["createdAt"], "2026-07-10T00:00:00Z")  # from `timestamp`
        self.assertEqual(first["score"], 0.9)                          # kept off the wrapper
        self.assertNotIn("observation", first)
        self.assertNotIn("tokens_used", result)                        # aggregate fields still stripped
        self.assertEqual(result["results"][1]["id"], "obs_2")
        for k in ("tokens_used", "truncated", "format", "text"):
            self.assertNotIn(k, result)

    def test_search_fails_closed_on_non_list_results(self) -> None:
        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            return _FakeResponse(
                {"results": {"leak": {"project": "OTHER-Q"}}, "text": "AGGREGATE SECRET", "tokens_used": 9999}
            )

        import mcp_governance_gateway.memory_backend as memory_backend

        original = memory_backend.request.urlopen
        memory_backend.request.urlopen = fake_urlopen
        try:
            backend = HttpMemoryBackend(
                base_url="http://memory.internal:3111", backend_token=None,
                search_path="/agentmemory/search", save_path="/agentmemory/remember",
            )
            result = backend.search(
                "q", 10, RequestContext(actor="u", project="example-project", client="t", request_id="r"),
            )
        finally:
            memory_backend.request.urlopen = original

        self.assertEqual(result, {"results": [], "count": 0})

    def test_search_caps_results_at_requested_limit(self) -> None:
        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            # backend ignores `limit` and returns more than asked
            return _FakeResponse({"results": [{"observation": {"id": f"o{i}"}} for i in range(20)]})

        import mcp_governance_gateway.memory_backend as memory_backend

        original = memory_backend.request.urlopen
        memory_backend.request.urlopen = fake_urlopen
        try:
            backend = HttpMemoryBackend(
                base_url="http://memory.internal:3111", backend_token=None,
                search_path="/agentmemory/search", save_path="/agentmemory/remember",
            )
            result = backend.search(
                "q", 5, RequestContext(actor="u", project="example-project", client="t", request_id="r"),
            )
        finally:
            memory_backend.request.urlopen = original

        self.assertEqual(result["count"], 5)
        self.assertEqual(len(result["results"]), 5)

    def test_save_maps_to_remember_and_returns_validated_nested_id(self) -> None:
        captured: dict[str, object] = {}

        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            captured["url"] = req.full_url
            captured["method"] = req.get_method()
            captured["body"] = json.loads(req.data.decode("utf-8"))
            captured["auth"] = req.headers.get("Authorization")
            return _FakeResponse({"success": True, "memory": {"id": "mem_1", "project": "example-project"}})

        import mcp_governance_gateway.memory_backend as memory_backend

        original = memory_backend.request.urlopen
        memory_backend.request.urlopen = fake_urlopen
        try:
            backend = HttpMemoryBackend(
                base_url="http://memory.internal:3111", backend_token="backend-token",
                search_path="/agentmemory/search", save_path="/agentmemory/remember",
            )
            result = backend.save(
                "remember this", ["phase1"],
                RequestContext(actor="user@example.com", project="example-project", client="test", request_id="req_1"),
            )
        finally:
            memory_backend.request.urlopen = original

        self.assertEqual(result, {"saved": True, "project": "example-project", "id": "mem_1"})
        self.assertEqual(captured["url"], "http://memory.internal:3111/agentmemory/remember")
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["auth"], "Bearer backend-token")
        self.assertEqual(
            captured["body"],
            {
                "content": "remember this",
                "project": "example-project",
                "concepts": ["phase1", "actor:user@example.com"],
            },
        )

    def test_save_does_not_echo_hostile_backend_body(self) -> None:
        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            return _FakeResponse(
                {
                    "success": True,
                    "memory": {"id": "mem_9", "project": "OTHER-PROJECT-Q"},
                    "neighbors": [{"content": "Q private", "project": "Q"}],
                    "text": "aggregate from Q",
                }
            )

        import mcp_governance_gateway.memory_backend as memory_backend

        original = memory_backend.request.urlopen
        memory_backend.request.urlopen = fake_urlopen
        try:
            backend = HttpMemoryBackend(
                base_url="http://memory.internal:3111", backend_token=None,
                search_path="/agentmemory/search", save_path="/agentmemory/remember",
            )
            result = backend.save(
                "x", [],
                RequestContext(actor="u", project="example-project", client="t", request_id="r"),
            )
        finally:
            memory_backend.request.urlopen = original

        # backend body not echoed; and a project mismatch (memory.project != caller
        # project) means the foreign id is not surfaced
        self.assertEqual(result, {"saved": True, "project": "example-project"})
        self.assertNotIn("id", result)
        self.assertNotIn("neighbors", result)
        self.assertNotIn("text", result)

    def test_list_filters_to_project_and_sorts_newest_first(self) -> None:
        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            # /memories does not filter by project server-side; the gateway must.
            return _FakeResponse(
                {
                    "memories": [
                        {"id": "m1", "project": "example-project", "title": "a", "content": "A",
                         "type": "decision", "updatedAt": "2026-06-01"},
                        {"id": "m2", "project": "OTHER", "title": "leak", "content": "B", "updatedAt": "2026-06-09"},
                        {"id": "m3", "project": "example-project", "title": "c", "content": "C",
                         "concepts": ["x"], "updatedAt": "2026-06-05"},
                    ],
                    "total": 3, "limit": 500, "offset": 0,
                }
            )

        import mcp_governance_gateway.memory_backend as memory_backend

        original = memory_backend.request.urlopen
        memory_backend.request.urlopen = fake_urlopen
        try:
            backend = HttpMemoryBackend(
                base_url="http://memory.internal:3111", backend_token=None,
                search_path="/agentmemory/search", save_path="/agentmemory/remember",
            )
            result = backend.list(
                10, 0, RequestContext(actor="u", project="example-project", client="t", request_id="r"),
            )
        finally:
            memory_backend.request.urlopen = original

        self.assertEqual(result["total"], 2)  # OTHER-project item dropped
        self.assertEqual([m["id"] for m in result["memories"]], ["m3", "m1"])  # newest first
        self.assertNotIn("OTHER", [m["project"] for m in result["memories"]])
        self.assertEqual(result["memories"][1]["concepts"], [])  # missing concepts normalized to []

    def test_list_paginates_over_filtered_set(self) -> None:
        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            return _FakeResponse(
                {
                    "memories": [
                        {"id": "m1", "project": "p", "updatedAt": "2026-06-01"},
                        {"id": "m3", "project": "p", "updatedAt": "2026-06-05"},
                        {"id": "m2", "project": "p", "updatedAt": "2026-06-09"},
                    ],
                    "total": 3, "limit": 500, "offset": 0,
                }
            )

        import mcp_governance_gateway.memory_backend as memory_backend

        original = memory_backend.request.urlopen
        memory_backend.request.urlopen = fake_urlopen
        try:
            backend = HttpMemoryBackend(
                base_url="http://memory.internal:3111", backend_token=None,
                search_path="/agentmemory/search", save_path="/agentmemory/remember",
            )
            page = backend.list(1, 1, RequestContext(actor="u", project="p", client="t", request_id="r"))
        finally:
            memory_backend.request.urlopen = original

        self.assertEqual(page["total"], 3)
        self.assertEqual(page["count"], 1)
        self.assertEqual([m["id"] for m in page["memories"]], ["m3"])  # newest-first [m2,m3,m1], offset 1
        self.assertEqual(page["offset"], 1)


class MemoryListingShapeTests(unittest.TestCase):
    """What the listing endpoints keep when the limit bites."""

    def _backend(self, path, payload):
        import mcp_governance_gateway.memory_backend as memory_backend

        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            self.assertIn(path, req.full_url)
            return _FakeResponse(payload)

        original = memory_backend.request.urlopen
        memory_backend.request.urlopen = fake_urlopen
        self.addCleanup(lambda: setattr(memory_backend.request, "urlopen", original))
        return HttpMemoryBackend(
            base_url="http://memory.internal:3111", backend_token=None,
            search_path="/agentmemory/search", save_path="/agentmemory/remember",
        )

    @staticmethod
    def _ctx() -> RequestContext:
        return RequestContext(actor="u", project="p", client="t", request_id="r")

    def test_lessons_keep_the_most_reinforced_when_capped(self) -> None:
        backend = self._backend("/lessons", {"lessons": [
            {"id": "l1", "project": "p", "content": "weak", "confidence": 0.2},
            {"id": "l2", "project": "p", "content": "strong", "confidence": 0.95},
            {"id": "l3", "project": "p", "content": "mid", "confidence": 0.6},
            {"id": "l4", "project": "p", "content": "unscored"},  # missing confidence sorts last, no crash
        ]})
        out = backend.lesson_list(2, self._ctx())
        self.assertEqual([lesson["id"] for lesson in out["lessons"]], ["l2", "l3"])

    def test_a_malformed_confidence_does_not_take_the_listing_down(self) -> None:
        # Adversarial review, 2026-08-10: the sort key negated the raw field, so a
        # string confidence raised TypeError outside MemoryBackendError handling.
        backend = self._backend("/lessons", {"lessons": [
            {"id": "l1", "project": "p", "content": "numeric", "confidence": 0.9},
            {"id": "l2", "project": "p", "content": "stringly", "confidence": "0.95"},
            {"id": "l3", "project": "p", "content": "nonsense", "confidence": "high"},
        ]})
        out = backend.lesson_list(10, self._ctx())
        self.assertEqual(out["count"], 3)
        # a parseable string still sorts by its value; an unparseable one sorts last
        self.assertEqual([lesson["id"] for lesson in out["lessons"]], ["l2", "l1", "l3"])

    def test_action_list_is_the_live_board_unless_asked_otherwise(self) -> None:
        payload = {"actions": [
            {"id": "a1", "project": "p", "title": "open", "status": "pending"},
            {"id": "a2", "project": "p", "title": "shipped", "status": "done"},
            {"id": "a3", "project": "p", "title": "stuck", "status": "blocked"},
        ]}
        open_only = self._backend("/actions", payload).action_list(10, self._ctx())
        self.assertEqual([a["id"] for a in open_only["actions"]], ["a1", "a3"])
        self.assertEqual(open_only["count"], 2)
        everything = self._backend("/actions", payload).action_list(10, self._ctx(), include_done=True)
        self.assertEqual([a["id"] for a in everything["actions"]], ["a1", "a2", "a3"])

    def test_done_actions_cannot_crowd_open_ones_out_of_the_limit(self) -> None:
        # The whole point of the default: with the cap at 1, a done action listed
        # first must not be the one thing the caller sees.
        backend = self._backend("/actions", {"actions": [
            {"id": "done", "project": "p", "title": "d", "status": "done"},
            {"id": "live", "project": "p", "title": "l", "status": "active"},
        ]})
        self.assertEqual([a["id"] for a in backend.action_list(1, self._ctx())["actions"]], ["live"])


class CiArtifactRouteTests(unittest.TestCase):
    """/ci/artifact is the only path in this gateway that returns raw bytes, so its
    gates are tested against a live server rather than through the backend alone."""

    # Genuinely larger than one stream chunk. Adversarial review, 2026-08-10: the
    # previous 50,000 bytes was SMALLER than STREAM_CHUNK (65,536), so the test
    # claimed multi-chunk coverage while exercising a single read.
    PAYLOAD = b"IMAGEBYTES" * 20_000

    def _server(self, project="proj-a", artifact_path="out/image.bin",
                max_bytes=None, max_concurrent=None, declare_length=True, block=None):
        import threading
        import time

        tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"tokens": [
            {"token": "tok-a", "actor": "a", "project": "proj-a", "roles": ["developer"]},
            {"token": "tok-b", "actor": "b", "project": "proj-b", "roles": ["developer"]},
        ]}, tf)
        tf.close()
        self.addCleanup(lambda: os.unlink(tf.name))
        jobs = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"proj-a": ["swarm-build"]}, jobs)
        jobs.close()
        self.addCleanup(lambda: os.unlink(jobs.name))
        settings = Settings(
            host="127.0.0.1", port=0, token_file=tf.name, allowed_origins=(),
            memory_base_url="http://127.0.0.1:59999", memory_backend_token=None,
            memory_search_path="/s", memory_save_path="/r", memory_timeout_sec=2,
            memory_save_max_text_bytes=32768, memory_user_writes_per_minute=30,
            memory_project_writes_per_day=5000, memory_user_reads_per_minute=120,
            jenkins_base_url="https://jenkins.example", ci_jobs_file=jobs.name,
            **({"ci_artifact_max_bytes": max_bytes} if max_bytes else {}),
            **({"ci_artifact_max_concurrent": max_concurrent} if max_concurrent else {}),
        )
        srv = build_server(settings)
        self.audit = ListAuditSink()
        srv.audit_sink = self.audit

        listing = json.dumps({"number": 291, "artifacts": [
            {"fileName": artifact_path.rsplit("/", 1)[-1], "relativePath": artifact_path},
        ]}).encode()
        payload = self.PAYLOAD

        self.reads: list[int] = []
        self.closed: list[bool] = []
        reads, closed = self.reads, self.closed

        class _Upstream:
            headers = ({"Content-Type": "application/octet-stream", "Content-Length": str(len(payload))}
                       if declare_length else {"Content-Type": "application/octet-stream"})

            def __init__(self):
                self._left = payload

            def read(self, n):
                # `block` lets a test hold a stream open deterministically, so a
                # concurrency cap can be observed instead of raced against.
                if block is not None and reads:
                    block.wait(timeout=5)
                chunk, self._left = self._left[:n], self._left[n:]
                reads.append(len(chunk))
                return chunk

            def close(self):
                closed.append(True)

        srv.ci_backend._fetch = lambda path: listing          # type: ignore[method-assign]
        srv.ci_backend._open = lambda path: _Upstream()       # type: ignore[method-assign]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        time.sleep(0.2)
        return srv.server_address[1]

    def _get(self, port, query, token="tok-a"):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        conn.request("GET", "/ci/artifact?" + query, headers=headers)
        response = conn.getresponse()
        body = response.read()
        conn.close()
        return response, body

    def test_streams_the_file_with_a_download_disposition(self) -> None:
        from mcp_governance_gateway.ci_backend import STREAM_CHUNK

        port = self._server()
        response, body = self._get(port, "job=swarm-build&build=291&path=out/image.bin")
        self.assertEqual(response.status, 200)
        self.assertEqual(body, self.PAYLOAD)  # complete across chunk boundaries
        self.assertIn('filename="image.bin"', response.getheader("Content-Disposition") or "")
        # the body really was reassembled from several reads, and upstream was closed
        self.assertGreater(len(self.PAYLOAD), STREAM_CHUNK)
        self.assertGreater(len([n for n in self.reads if n > 0]), 1)
        self.assertTrue(self.closed)

    def test_a_filename_cannot_inject_response_headers(self) -> None:
        # Adversarial review, 2026-08-10: send_header does no CRLF validation, so a
        # listed basename containing a line break emitted attacker-chosen headers.
        port = self._server(artifact_path="out/ev\r\nX-Injected: yes.bin")
        response, body = self._get(port, "job=swarm-build&build=291&path=out/ev%0d%0aX-Injected:%20yes.bin")
        self.assertEqual(response.status, 200)
        self.assertIsNone(response.getheader("X-Injected"))
        self.assertNotIn("\r", response.getheader("Content-Disposition") or "")
        self.assertNotIn("\n", response.getheader("Content-Disposition") or "")
        self.assertEqual(body, self.PAYLOAD)

    def test_no_token_is_rejected_before_anything_is_fetched(self) -> None:
        port = self._server()
        response, _ = self._get(port, "job=swarm-build&path=out/image.bin", token=None)
        self.assertEqual(response.status, 401)

    def test_another_tenants_token_cannot_reach_the_job(self) -> None:
        port = self._server()
        response, _ = self._get(port, "job=swarm-build&path=out/image.bin", token="tok-b")
        self.assertEqual(response.status, 404)

    def test_a_path_the_build_does_not_list_is_refused(self) -> None:
        port = self._server()
        for path in ("../../../etc/passwd", "out/secret.bin"):
            with self.subTest(path=path):
                response, _ = self._get(port, "job=swarm-build&path=" + path)
                self.assertEqual(response.status, 404)

    def test_the_transfer_itself_is_audited(self) -> None:
        # Design review, 2026-08-10: every MCP tool call was audited, and the one
        # operation that moved bytes was not -- the record showed only the preceding
        # metadata lookup.
        port = self._server()
        self._get(port, "job=swarm-build&build=291&path=out/image.bin")
        event = self.audit.events[-1]
        self.assertEqual(event.tool, "ci.artifact.download")
        self.assertEqual(event.outcome, "ok")
        self.assertEqual(event.resource_id, "swarm-build:out/image.bin")
        self.assertEqual(event.duration_ms, len(self.PAYLOAD))  # bytes delivered

    def test_a_declared_size_over_the_cap_is_refused_before_streaming(self) -> None:
        port = self._server(max_bytes=1024)
        response, body = self._get(port, "job=swarm-build&build=291&path=out/image.bin")
        self.assertEqual(response.status, 413)
        self.assertEqual(self.audit.events[-1].outcome, "rejected")
        self.assertNotIn(b"IMAGEBYTES", body)

    def test_a_dishonest_upstream_cannot_buy_an_unbounded_transfer(self) -> None:
        # No Content-Length to check up front: the cap has to hold on the stream.
        port = self._server(max_bytes=100_000, declare_length=False)
        try:
            self._get(port, "job=swarm-build&build=291&path=out/image.bin")
        except Exception:
            pass  # a truncated response is the point; the client may see a short read
        self.assertEqual(self.audit.events[-1].outcome, "truncated")

    def test_concurrent_streams_are_capped(self) -> None:
        # A stream holds a thread and an upstream connection for its whole duration,
        # so the second one must be refused, not queued behind the first.
        import http.client
        import threading

        gate = threading.Event()
        port = self._server(max_concurrent=1, block=gate)
        first = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        first.request("GET", "/ci/artifact?job=swarm-build&build=291&path=out/image.bin",
                      headers={"Authorization": "Bearer tok-a"})
        first_response = first.getresponse()
        first_response.read(10)          # the slot is now held, deterministically
        try:
            second, _ = self._get(port, "job=swarm-build&build=291&path=out/image.bin")
            self.assertEqual(second.status, 503)
            self.assertEqual(self.audit.events[-1].outcome, "rejected")
        finally:
            gate.set()                   # let the first stream finish
            try:
                first_response.read()
            except Exception:
                pass
            first.close()

    def test_missing_arguments_are_a_bad_request(self) -> None:
        port = self._server()
        for query in ("job=swarm-build", "path=out/image.bin", ""):
            with self.subTest(query=query):
                self.assertEqual(self._get(port, query)[0].status, 400)


class HttpServerKeepAliveTests(unittest.TestCase):
    def test_connection_is_kept_alive_for_followup_request(self) -> None:
        # MCP clients reuse one persistent connection: initialize, then send
        # notifications/initialized on the SAME socket. An HTTP/1.0 server closes
        # after the first response, which the client sees as ECONNRESET. Verify the
        # server speaks HTTP/1.1 keep-alive so the followup request reuses the socket.
        import http.client
        import threading
        import time

        tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"tokens": [{"token": "ka", "actor": "a", "project": "p", "roles": ["developer"]}]}, tf)
        tf.close()
        settings = Settings(
            host="127.0.0.1", port=0, token_file=tf.name, allowed_origins=(),
            memory_base_url="http://127.0.0.1:59999", memory_backend_token=None,
            memory_search_path="/s", memory_save_path="/r", memory_timeout_sec=2,
            memory_save_max_text_bytes=32768, memory_user_writes_per_minute=30,
            memory_project_writes_per_day=5000, memory_user_reads_per_minute=120,
        )
        srv = build_server(settings)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            time.sleep(0.2)
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            hdr = {"Authorization": "Bearer ka", "Content-Type": "application/json"}
            conn.request("POST", "/mcp", json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}},
            }), hdr)
            r1 = conn.getresponse(); r1.read()
            self.assertEqual(r1.version, 11)       # HTTP/1.1
            self.assertFalse(r1.will_close)        # keep-alive: server does not close
            sock = conn.sock
            conn.request("POST", "/mcp",
                         json.dumps({"jsonrpc": "2.0", "id": None, "method": "notifications/initialized"}), hdr)
            r2 = conn.getresponse(); r2.read()
            self.assertEqual(r2.status, 202)
            self.assertIs(conn.sock, sock)         # same socket reused, not reconnected
        finally:
            srv.shutdown()
            Path(tf.name).unlink()


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
        import mcp_governance_gateway.issue_backend as issue_backend

        original = issue_backend.request.urlopen
        issue_backend.request.urlopen = router
        self.addCleanup(lambda: setattr(issue_backend.request, "urlopen", original))
        return RedmineHttpBackend(base_url="http://redmine.internal/redmine", api_key="k")

    @staticmethod
    def _ctx() -> RequestContext:
        return RequestContext(actor="u", project="p", client="t", request_id="r", issue_project="97")

    def test_get_enforces_project_scope_and_normalizes(self) -> None:
        def router(req, timeout):  # type: ignore[no-untyped-def]
            url = req.full_url
            if "/projects/97.json" in url:
                return _FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issues/123.json" in url:
                return _FakeResponse(
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
                return _FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issues/999.json" in url:
                return _FakeResponse({"issue": {"id": 999, "project": {"id": 55, "name": "Other"}, "subject": "X"}})
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
                return _FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issues.json" in url:
                captured["url"] = url
                return _FakeResponse(
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
                return _FakeResponse({"project": {"id": 97, "name": "Q"}})
            if url.endswith("/issues.json") and req.get_method() == "POST":
                captured["body"] = json.loads(req.data.decode("utf-8"))
                return _FakeResponse({"issue": {"id": 500, "project": {"id": 97, "name": "Q"}, "subject": "New"}})
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
                return _FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issues/55.json" in url and method == "GET":
                return _FakeResponse({"issue": {"id": 55, "project": {"id": 97, "name": "Q"}}})
            if "/issues/55.json" in url and method == "PUT":
                captured["body"] = json.loads(req.data.decode("utf-8"))
                return _FakeResponse({})
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
                return _FakeResponse(_STATUS_ROWS)
            if "/projects/97.json" in url:
                return _FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issues/12.json" in url and method == "GET":
                return _FakeResponse({"issue": {"id": 12, "project": {"id": 97, "name": "Q"}}})
            if "/issues/12.json" in url and method == "PUT":
                captured["body"] = json.loads(req.data.decode("utf-8"))
                return _FakeResponse({})
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
                return _FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issues.json" in url:
                return _FakeResponse({"issues": [
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
                return _FakeResponse({"project": {"id": 97, "name": "Q"}})
            if url.endswith("/issues.json") and req.get_method() == "POST":
                return _FakeResponse({"issue": {"id": 7, "project": {"id": 55, "name": "Other"}, "subject": "X"}})
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
                return _FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issues.json" in url:
                return _FakeResponse(big)
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
                return _FakeResponse({"project": {"id": 97, "name": "Q"}})
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
        import mcp_governance_gateway.issue_backend as issue_backend

        self.fetches: list[str] = []
        self.rows = rows

        def router(req, timeout):  # type: ignore[no-untyped-def]
            url, method = req.full_url, req.get_method()
            if "/issue_statuses.json" in url:
                self.fetches.append(url)
                return _FakeResponse(self.rows)
            if "/projects/97.json" in url:
                return _FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issues/12.json" in url and method == "GET":
                return _FakeResponse({"issue": {"id": 12, "project": {"id": 97, "name": "Q"}}})
            if "/issues/12.json" in url and method == "PUT":
                self.put = json.loads(req.data.decode("utf-8"))
                return _FakeResponse({})
            raise AssertionError((method, url))

        original = issue_backend.request.urlopen
        issue_backend.request.urlopen = router
        self.addCleanup(lambda: setattr(issue_backend.request, "urlopen", original))
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
        import mcp_governance_gateway.issue_backend as issue_backend

        clock = [1000.0]
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
        import mcp_governance_gateway.issue_backend as issue_backend

        self.fetches: list[str] = []
        self.writes: list[dict] = []
        self.other_project_issue = "555"

        def router(req, timeout):  # type: ignore[no-untyped-def]
            url, method = req.full_url, req.get_method()
            self.fetches.append(f"{method} {url}")
            if "/issue_statuses.json" in url:
                return _FakeResponse(_STATUS_ROWS)
            if "/trackers.json" in url:
                return _FakeResponse(_TRACKER_ROWS)
            if "/issue_priorities.json" in url:
                return _FakeResponse(_PRIORITY_ROWS)
            if "/issue_categories.json" in url:
                return _FakeResponse(_CATEGORY_ROWS)
            if "/projects/97.json" in url:
                return _FakeResponse({"project": {"id": 97, "name": "Q"}})
            if f"/issues/{self.other_project_issue}.json" in url:
                # exists, but belongs to another tenant
                return _FakeResponse({"issue": {"id": 555, "project": {"id": 55, "name": "Other"}}})
            if "/issues/12.json" in url and method == "GET":
                return _FakeResponse({"issue": {
                    "id": 12, "project": {"id": 97}, "subject": "S", "description": "the body",
                    "status": {"name": "Resolved"}, "category": {"id": 61, "name": "Firmware"},
                }})
            if "/issues/900.json" in url and method == "GET":
                return _FakeResponse({"issue": {"id": 900, "project": {"id": 97}}})
            if method in ("POST", "PUT"):
                self.writes.append(json.loads(req.data.decode("utf-8"))["issue"])
                return _FakeResponse({"issue": {"id": 12, "project": {"id": 97}}})
            raise AssertionError((method, url))

        original = issue_backend.request.urlopen
        issue_backend.request.urlopen = router
        self.addCleanup(lambda: setattr(issue_backend.request, "urlopen", original))
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
        import mcp_governance_gateway.issue_backend as issue_backend

        keys: list[str | None] = []

        def router(req, timeout):  # type: ignore[no-untyped-def]
            keys.append(req.headers.get("X-redmine-api-key"))
            if "/projects/97.json" in req.full_url:
                return _FakeResponse({"project": {"id": 97, "name": "Q"}})
            return _FakeResponse({"issues": [{"id": 7, "project": {"id": 97}}]})

        original = issue_backend.request.urlopen
        issue_backend.request.urlopen = router
        self.addCleanup(lambda: setattr(issue_backend.request, "urlopen", original))
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
                return _FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issue_statuses.json" in req.full_url:
                return _FakeResponse({"issue_statuses": [{"id": 1, "name": "Open"}]})
            if "/issues.json" in req.full_url:
                return _FakeResponse({"issues": [{"id": 7, "project": {"id": 97}}]})
            return _FakeResponse({"issue": {"id": 7, "project": {"id": 97}, "subject": "s"}})
        return router

    def _patch(self, router):
        import mcp_governance_gateway.issue_backend as issue_backend
        original = issue_backend.request.urlopen
        issue_backend.request.urlopen = router
        self.addCleanup(lambda: setattr(issue_backend.request, "urlopen", original))

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
        import mcp_governance_gateway.issue_backend as issue_backend
        seen: list[tuple[str, str | None]] = []

        def router(req, timeout):  # type: ignore[no-untyped-def]
            method = req.get_method()
            seen.append((req.full_url, req.headers.get("X-redmine-api-key")))
            if "/projects/97.json" in req.full_url:
                return _FakeResponse({"project": {"id": 97, "name": "Q"}})
            if "/issue_statuses.json" in req.full_url:
                return _FakeResponse({"issue_statuses": [{"id": 1, "name": "OPEN"}]})
            if method == "GET":
                return _FakeResponse({"issue": {"id": 7, "project": {"id": 97}, "subject": "s"}})
            return _FakeResponse({"issue": {"id": 7, "project": {"id": 97}}})

        original = issue_backend.request.urlopen
        issue_backend.request.urlopen = router
        self.addCleanup(lambda: setattr(issue_backend.request, "urlopen", original))
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


class SchemaDefaultsMatchBehaviourTests(unittest.TestCase):
    """A declared `default` the handler does not honour is worse than none: the
    client reads the schema and plans around a number the server ignores."""

    def setUp(self) -> None:
        self.backend = FakeMemoryBackend()
        self.app = GatewayApp(memory_backend=self.backend, audit_sink=ListAuditSink())
        self.principal = Principal(actor="u", project="proj", roles=("developer",), token_id="t")

    def _declared(self, tool: str, field: str):
        spec = next(s for s in tool_definitions() if s["name"] == tool)
        return spec["inputSchema"]["properties"][field]["default"]

    def _omit_and_capture(self, tool: str, arguments: dict | None = None) -> dict:
        self.app.handle_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": tool, "arguments": arguments or {}}},
            self.principal,
        )
        return self.backend.calls[-1]

    def test_omitted_limit_uses_the_declared_default(self) -> None:
        for tool, arguments in [
            ("memory.search", {"query": "q"}),
            ("memory.list", {}),
            ("memory.lesson_list", {}),
            ("memory.action_list", {}),
        ]:
            with self.subTest(tool=tool):
                self.assertEqual(self._omit_and_capture(tool, arguments)["limit"], self._declared(tool, "limit"))

    def test_omitted_include_done_uses_the_declared_default(self) -> None:
        call = self._omit_and_capture("memory.action_list")
        self.assertEqual(call["include_done"], self._declared("memory.action_list", "includeDone"))


class ConfirmationFeedbackTests(unittest.TestCase):
    """What a caller sees when a confirm is supplied and does not resolve."""

    def setUp(self) -> None:
        self.issues = FakeIssueBackend()
        self.app = GatewayApp(
            memory_backend=FakeMemoryBackend(),
            audit_sink=ListAuditSink(),
            issue_backend=self.issues,
            confirmation=ConfirmationStore(),
        )
        self.principal = Principal(
            actor="u@x", project="proj", roles=("issue_writer",), token_id="t", issue_project="97",
        )

    def _call(self, arguments: dict):
        response = self.app.handle_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "issues.create", "arguments": arguments}},
            self.principal,
        )
        assert response is not None
        return response["result"]["structuredContent"]

    def test_first_call_carries_no_error_field(self) -> None:
        out = self._call({"subject": "s"})
        self.assertTrue(out["confirmationRequired"])
        self.assertNotIn("confirmError", out)

    def test_a_rejected_confirm_explains_itself_instead_of_looking_like_a_first_call(self) -> None:
        out = self._call({"subject": "s", "confirm": "not-a-real-id"})
        self.assertTrue(out["confirmationRequired"])
        self.assertIn("unknown or already-used", out["confirmError"])
        # a usable fresh id still comes back, so the caller can just retry properly
        self.assertTrue(out["confirmationId"])
        self.assertEqual(self.issues.calls, [])

    def test_a_changed_argument_names_the_argument(self) -> None:
        cid = self._call({"subject": "original"})["confirmationId"]
        out = self._call({"subject": "edited", "confirm": cid})
        self.assertIn("subject", out["confirmError"])
        self.assertIn("byte-for-byte", out["confirmError"])
        self.assertEqual(self.issues.calls, [])

    def test_long_text_is_digested_in_the_echo_but_bound_in_full(self) -> None:
        body = "x" * 500
        first = self._call({"subject": "s", "description": body})
        echoed = first["arguments"]["description"]
        self.assertIn("500 chars", echoed)
        self.assertIn("sha256:", echoed)
        self.assertNotIn("xxxx", echoed)  # the body itself is not repeated back
        # the gate is bound to the FULL value: resending the echo must not commit
        self.assertIn("confirmError", self._call({"subject": "s", "description": echoed, "confirm": first["confirmationId"]}))
        self.assertEqual(self.issues.calls, [])
        # ... and resending the real body does commit
        out = self._call({"subject": "s", "description": body, "confirm": first["confirmationId"]})
        self.assertTrue(out["created"])

    def test_short_arguments_still_echo_verbatim(self) -> None:
        out = self._call({"subject": "a short subject"})
        self.assertEqual(out["arguments"]["subject"], "a short subject")


class ConfirmationStoreTests(unittest.TestCase):
    @staticmethod
    def _principal(token_id: str = "t", issue_project: str = "97") -> Principal:
        return Principal(
            actor="u@x", project="proj", roles=("issue_writer",), token_id=token_id, issue_project=issue_project
        )

    def test_single_use_under_concurrency(self) -> None:
        import threading

        for _ in range(20):
            store = ConfirmationStore()
            principal = self._principal()
            cid = store.issue(principal, "issues.create", {"subject": "x"})
            results: list[object] = []
            barrier = threading.Barrier(2)

            def worker() -> None:
                barrier.wait()
                try:
                    results.append(store.verify(principal, "issues.create", {"subject": "x"}, cid)[0])
                except Exception as exc:  # noqa: BLE001 - record any unhandled error
                    results.append(f"EXC:{type(exc).__name__}")

            threads = [threading.Thread(target=worker) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(results.count(True), 1, results)
            self.assertEqual(results.count(False), 1, results)
            self.assertFalse(any(isinstance(r, str) for r in results), results)  # no exception thread

    def test_confirmation_bound_to_token_and_issue_project(self) -> None:
        store = ConfirmationStore()
        p_a = self._principal(token_id="A", issue_project="97")
        args = {"subject": "x"}
        cid = store.issue(p_a, "issues.create", args)
        # a different token id must not verify
        self.assertFalse(store.verify(self._principal(token_id="B"), "issues.create", args, cid)[0])
        # a different issue project must not verify
        self.assertFalse(store.verify(self._principal(issue_project="98"), "issues.create", args, cid)[0])
        # the exact principal still verifies (and is then consumed)
        self.assertEqual(store.verify(p_a, "issues.create", args, cid), (True, None))

    def test_another_principals_nonce_is_indistinguishable_from_a_nonexistent_one(self) -> None:
        # The reason strings must not become an oracle: a foreign caller holding a
        # guessed or leaked nonce learns nothing about whether it exists.
        store = ConfirmationStore()
        args = {"subject": "x"}
        cid = store.issue(self._principal(token_id="A"), "issues.create", args)
        foreign = store.verify(self._principal(token_id="B"), "issues.create", args, cid)
        never_issued = store.verify(self._principal(token_id="B"), "issues.create", args, "made-up-nonce")
        self.assertEqual(foreign, never_issued)
        # ... and the same holds for the right principal on the wrong tool
        wrong_tool = store.verify(self._principal(token_id="A"), "issues.add_note", args, cid)
        self.assertEqual(wrong_tool, never_issued)
        # the entry survived all of that: only the rightful caller consumes it
        self.assertTrue(store.verify(self._principal(token_id="A"), "issues.create", args, cid)[0])

    def test_no_confirm_supplied_is_not_reported_as_a_failure(self) -> None:
        # An ordinary first call has nothing to explain; only a supplied-and-rejected
        # confirm does, which is what lets the gate surface confirmError selectively.
        store = ConfirmationStore()
        self.assertEqual(store.verify(self._principal(), "issues.create", {"subject": "x"}, None), (False, None))
        ok, reason = store.verify(self._principal(), "issues.create", {"subject": "x"}, "")
        self.assertFalse(ok)
        self.assertIn("empty or not a string", reason or "")

    def test_expiry_says_so_rather_than_looking_unknown(self) -> None:
        now = [1000.0]
        store = ConfirmationStore(ttl_sec=300, clock=lambda: now[0])
        principal = self._principal()
        cid = store.issue(principal, "issues.create", {"subject": "x"})
        now[0] += 301
        ok, reason = store.verify(principal, "issues.create", {"subject": "x"}, cid)
        self.assertFalse(ok)
        self.assertIn("expired", reason or "")
        self.assertIn("300s", reason or "")

    def test_changed_argument_is_named_with_both_digests(self) -> None:
        store = ConfirmationStore()
        principal = self._principal()
        cid = store.issue(principal, "issues.create", {"subject": "x", "description": "keep"})
        ok, reason = store.verify(
            principal, "issues.create", {"subject": "y", "description": "keep"}, cid
        )
        self.assertFalse(ok)
        self.assertIn("subject", reason or "")
        self.assertNotIn("description", reason or "")  # unchanged fields are not noise
        # both sides of the comparison are shown, so a caller can diff by eye
        self.assertIn("confirmed", reason or "")
        self.assertIn("got", reason or "")

    def test_a_retyped_argument_is_still_named(self) -> None:
        # Adversarial review, 2026-08-10: "1" and 1 hashed identically, so the action
        # key changed (correctly) while the changed-argument list came out empty --
        # the gate rejected the call and then explained nothing.
        store = ConfirmationStore()
        principal = self._principal()
        cid = store.issue(principal, "issues.create", {"id": "1"})
        ok, reason = store.verify(principal, "issues.create", {"id": 1}, cid)
        self.assertFalse(ok)
        self.assertIn("id", reason or "")
        self.assertNotIn("changed since it was issued: .", reason or "")

    def test_the_echo_digest_still_lines_up_with_a_string_field(self) -> None:
        # The reason strings are meant to be diffable against the echo, which means
        # a plain string must keep hashing its raw utf-8.
        import hashlib
        from mcp_governance_gateway.mcp import _echo_args, _ECHO_MAX_CHARS

        body = "x" * (_ECHO_MAX_CHARS + 1)
        echoed = _echo_args({"description": body})["description"]
        self.assertIn(hashlib.sha256(body.encode()).hexdigest()[:8], echoed)
        self.assertEqual(
            ConfirmationStore._field_digests({"description": body})["description"],
            hashlib.sha256(body.encode()).hexdigest()[:8],
        )

    def test_a_dropped_argument_is_named_as_absent(self) -> None:
        store = ConfirmationStore()
        principal = self._principal()
        cid = store.issue(principal, "issues.create", {"subject": "x", "description": "d"})
        ok, reason = store.verify(principal, "issues.create", {"subject": "x"}, cid)
        self.assertFalse(ok)
        self.assertIn("description", reason or "")
        self.assertIn("absent", reason or "")


class _FakeResponse:
    def __init__(self, body: dict[str, object]) -> None:
        self._body = json.dumps(body).encode("utf-8")

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        return None

    def read(self, *args) -> bytes:  # type: ignore[no-untyped-def]
        return self._body


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
            # corrupt reload keeps last-good map; both tokens still authenticate
            self.assertEqual(auth.authenticate_header("Bearer usr").actor, "a@x")
            self.assertEqual(auth.authenticate_header("Bearer svc").project, "x")

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


class NormalizeActorTests(unittest.TestCase):
    def test_lesson_and_action_surface_actor_from_tags(self) -> None:
        from mcp_governance_gateway.memory_backend import _normalize_lesson, _normalize_action
        lesson = _normalize_lesson({"id": "l1", "project": "p", "content": "c", "confidence": 0.9,
                                    "reinforcements": 2, "tags": ["actor:alice@x"], "createdAt": "2026"})
        self.assertEqual(lesson["actor"], "alice@x")
        action = _normalize_action({"id": "a1", "project": "p", "title": "t", "status": "pending",
                                    "tags": ["misc", "actor:bob@x"], "createdAt": "2026"})
        self.assertEqual(action["actor"], "bob@x")
        # no actor tag present -> None (never crashes)
        self.assertIsNone(_normalize_lesson({"id": "l2", "tags": []})["actor"])
        self.assertIsNone(_normalize_action({"id": "a2"})["actor"])


if __name__ == "__main__":
    unittest.main()


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
