"""GatewayApp over the fakes: the JSON-RPC lifecycle, the memory tools, and the confirmation gate and store."""
from __future__ import annotations

import json
import unittest

from fakes import FakeIssueBackend, FakeMemoryBackend

from mcp_governance_gateway.audit import ListAuditSink
from mcp_governance_gateway.auth import Principal
from mcp_governance_gateway.confirm import ConfirmationStore
from mcp_governance_gateway.limits import InMemoryMemoryWriteLimiter, MemoryLimitConfig
from mcp_governance_gateway.mcp import GatewayApp, tool_definitions


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

    def test_an_unknown_tool_name_is_audited_under_a_fixed_name(self) -> None:
        # The tool field is the one caller-chosen string that would otherwise
        # reach the append-only audit log verbatim; a credential mistaken for a
        # tool name must not land there.
        sentinel = "ghp_" + "S3CRET" * 6
        bad = self.app.handle_rpc(
            {"jsonrpc": "2.0", "id": 27, "method": "tools/call",
             "params": {"name": sentinel, "arguments": {}}},
            self.principal,
        )
        assert bad is not None
        self.assertEqual(bad["error"]["code"], -32003)  # policy fails closed first
        event = self.audit.events[-1]
        self.assertEqual(event.tool, "unknown")
        self.assertEqual(event.outcome, "denied")
        self.assertNotIn(sentinel, json.dumps(event.to_json()))

    def test_an_argument_the_schema_does_not_declare_is_rejected(self) -> None:
        # `additionalProperties: false` is enforced by the gateway, not left to
        # the client: an undeclared key is -32602 and never reaches the backend.
        n = len(self.backend.calls)
        bad = self.app.handle_rpc(
            {"jsonrpc": "2.0", "id": 26, "method": "tools/call",
             "params": {"name": "memory.search", "arguments": {"query": "x", "project": "other"}}},
            self.principal,
        )
        assert bad is not None
        self.assertEqual(bad["error"]["code"], -32602)
        self.assertIn("project", bad["error"]["message"])
        self.assertEqual(len(self.backend.calls), n)
        self.assertEqual(self.audit.events[-1].outcome, "invalid")

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
        # undeclared names are audited under a fixed label, never verbatim
        self.assertEqual(self.audit.events[0].tool, "unknown")
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

            def worker(store=store, principal=principal, cid=cid, results=results, barrier=barrier) -> None:
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

        from mcp_governance_gateway.mcp import _ECHO_MAX_CHARS, _echo_args

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
