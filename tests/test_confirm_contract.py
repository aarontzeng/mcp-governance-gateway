"""What any confirmation backend must guarantee (confirm.ConfirmationBackend).

Written as a mixin so a shared implementation -- the roadmap's "durable write
outcomes and shared state" -- runs the same checks as the in-process store by
subclassing it with its own `make()`. The in-process store's own finer points
(eviction, expiry messages, field digests) are in test_gateway_app.py.
"""
from __future__ import annotations

import unittest
from typing import Any

from fakes import FakeIssueBackend, FakeMemoryBackend

from mcp_governance_gateway.audit import ListAuditSink
from mcp_governance_gateway.auth import Principal
from mcp_governance_gateway.confirm import ConfirmationBackend, ConfirmationStore
from mcp_governance_gateway.mcp import GatewayApp

_ME = Principal(actor="a", project="p", roles=("issue_writer",), token_id="t1", issue_project="97")
_ARGS = {"subject": "x"}


class ConfirmationContract:
    """Mix into a TestCase and define `make()`. `FLOOD` must exceed whatever
    total the implementation `make()` returns can hold."""

    FLOOD = 600

    def make(self) -> ConfirmationBackend:
        raise NotImplementedError

    def test_one_principal_flooding_prepares_does_not_evict_anothers(self: Any) -> None:
        # A token holding a write role could prepare without limit and push every
        # other tenant's pending confirmation out of a store shared by all of
        # them: the victim then saw "unknown or already-used" and had to start
        # over. A flood may only ever cost the flooder its own pending ids.
        store = self.make()
        victim = Principal(actor="v", project="other", roles=_ME.roles, token_id="tv", issue_project="98")
        kept = store.issue(victim, "issues.create", _ARGS)
        flooder_ids = [store.issue(_ME, "issues.create", {"subject": str(i)}) for i in range(self.FLOOD)]
        self.assertEqual(store.verify(victim, "issues.create", _ARGS, kept), (True, None))
        # ... and the flooder's newest prepare still works: the cost is its oldest.
        self.assertEqual(store.verify(_ME, "issues.create", {"subject": str(self.FLOOD - 1)}, flooder_ids[-1]),
                         (True, None))

    def test_an_issued_id_verifies_once(self: Any) -> None:
        store = self.make()
        cid = store.issue(_ME, "issues.create", _ARGS)
        self.assertEqual(store.verify(_ME, "issues.create", _ARGS, cid), (True, None))
        ok, reason = store.verify(_ME, "issues.create", _ARGS, cid)
        self.assertFalse(ok)
        self.assertIsNotNone(reason)

    def test_no_id_is_an_ordinary_first_call(self: Any) -> None:
        self.assertEqual(self.make().verify(_ME, "issues.create", _ARGS, None), (False, None))

    def test_ids_are_distinct(self: Any) -> None:
        store = self.make()
        self.assertEqual(len({store.issue(_ME, "issues.create", _ARGS) for _ in range(50)}), 50)

    def test_changed_arguments_do_not_verify(self: Any) -> None:
        store = self.make()
        cid = store.issue(_ME, "issues.create", _ARGS)
        self.assertFalse(store.verify(_ME, "issues.create", {"subject": "y"}, cid)[0])

    def test_another_principal_or_tool_sees_the_same_answer_as_for_a_made_up_id(self: Any) -> None:
        store = self.make()
        cid = store.issue(_ME, "issues.create", _ARGS)
        unknown = store.verify(_ME, "issues.create", _ARGS, "never-issued-id")
        others = [
            Principal(actor="b", project="p", roles=_ME.roles, token_id="t1", issue_project="97"),
            Principal(actor="a", project="q", roles=_ME.roles, token_id="t1", issue_project="97"),
            Principal(actor="a", project="p", roles=_ME.roles, token_id="t2", issue_project="97"),
            Principal(actor="a", project="p", roles=_ME.roles, token_id="t1", issue_project="98"),
        ]
        for other in others:
            self.assertEqual(store.verify(other, "issues.create", _ARGS, cid), unknown, other)
        self.assertEqual(store.verify(_ME, "issues.add_note", _ARGS, cid), unknown)
        # ... and the refusals did not consume it.
        self.assertEqual(store.verify(_ME, "issues.create", _ARGS, cid), (True, None))


class InProcessStoreContractTests(ConfirmationContract, unittest.TestCase):
    def make(self) -> ConfirmationBackend:
        # A small total, so FLOOD exceeds it without ten thousand issues.
        return ConfirmationStore(max_entries=500)


class InProcessStoreCapTests(unittest.TestCase):
    """The in-process store's own per-principal cap."""

    def test_the_cap_is_per_principal_not_per_tool(self) -> None:
        # Counted per (principal, tool), one token could hold the cap once per
        # write tool -- eleven of them today.
        store = ConfirmationStore(max_per_principal=4)
        issued = []
        for i in range(3):
            for tool in ("issues.create", "issues.add_note", "ci.rerun"):
                issued.append((tool, {"n": i}, store.issue(_ME, tool, {"n": i})))
        live = [cid for tool, args, cid in issued if store.verify(_ME, tool, args, cid)[0]]
        self.assertEqual(live, [cid for _tool, _args, cid in issued[-4:]], "the newest four, across tools")

    def test_bookkeeping_empties_as_ids_are_consumed_or_expire(self) -> None:
        now = [1000.0]
        store = ConfirmationStore(ttl_sec=10, clock=lambda: now[0])
        consumed = store.issue(_ME, "issues.create", _ARGS)
        store.issue(_ME, "issues.create", {"subject": "y"})
        store.verify(_ME, "issues.create", _ARGS, consumed)
        now[0] += 11
        store.issue(Principal(actor="z", project="p", roles=(), token_id="tz"), "issues.create", _ARGS)
        # Only the one just issued remains, in both maps.
        self.assertEqual(len(store._pending), 1)
        self.assertEqual(sum(len(o) for o in store._owned.values()), 1)
        self.assertEqual(len(store._owned), 1)

    def test_a_cap_below_one_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            ConfirmationStore(max_per_principal=0)

    def test_through_the_gateway_a_flooding_writer_cannot_cost_another_tenant_its_confirmation(self) -> None:
        app = GatewayApp(memory_backend=FakeMemoryBackend(), audit_sink=ListAuditSink(),
                         issue_backend=FakeIssueBackend(), confirmation=ConfirmationStore(max_entries=200))
        victim = Principal(actor="v", project="other", roles=("issue_writer",), token_id="tv", issue_project="98")

        def create(principal, arguments):
            return app.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                   "params": {"name": "issues.create", "arguments": arguments}},
                                  principal)["result"]["structuredContent"]

        pending = create(victim, {"subject": "mine"})
        for i in range(300):
            create(_ME, {"subject": f"flood {i}"})
        done = create(victim, {"subject": "mine", "confirm": pending["confirmationId"]})
        self.assertNotIn("confirmationRequired", done)
        self.assertNotIn("confirmError", done)


class _Recording:
    """A backend that is not ConfirmationStore: the gateway takes the interface."""

    def __init__(self) -> None:
        self.inner = ConfirmationStore()
        self.calls: list[str] = []

    def issue(self, principal, tool, args):
        self.calls.append(f"issue:{tool}")
        return self.inner.issue(principal, tool, args)

    def verify(self, principal, tool, args, provided):
        self.calls.append(f"verify:{tool}")
        return self.inner.verify(principal, tool, args, provided)


class GatewayTakesAnyBackendTests(unittest.TestCase):
    def test_the_two_step_write_runs_through_a_supplied_backend(self) -> None:
        backend = _Recording()
        issues = FakeIssueBackend()
        app = GatewayApp(memory_backend=FakeMemoryBackend(), audit_sink=ListAuditSink(),
                         issue_backend=issues, confirmation=backend)

        def call(arguments):
            return app.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                   "params": {"name": "issues.create", "arguments": arguments}}, _ME)

        first = call(_ARGS)["result"]["structuredContent"]
        self.assertTrue(first["confirmationRequired"])
        second = call({**_ARGS, "confirm": first["confirmationId"]})["result"]
        self.assertNotIn("confirmationRequired", second["structuredContent"])
        self.assertEqual(backend.calls, ["verify:issues.create", "issue:issues.create", "verify:issues.create"])


if __name__ == "__main__":
    unittest.main()
