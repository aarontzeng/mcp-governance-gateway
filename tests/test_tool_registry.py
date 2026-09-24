"""The registry is the one record policy, discovery and dispatch read, so the
three cannot disagree. These hold that, and the invariants a ToolSpec implies."""
from __future__ import annotations

import itertools
import unittest

from mcp_governance_gateway.auth import Principal
from mcp_governance_gateway.policy import Policy
from mcp_governance_gateway.tools import (
    HANDLERS,
    REGISTRY,
    SPECS_BY_NAME,
    tool_definitions,
    visible_tools,
)
from mcp_governance_gateway.tools.base import (
    FEATURE_CI,
    FEATURE_CI_WRITE,
    FEATURE_DOCS,
    FEATURE_DOCS_REVIEW,
    FEATURE_DOCS_STAGE,
    FEATURE_ISSUES,
    ISSUES,
    MEMORY,
    READ,
)

_FEATURES = (FEATURE_ISSUES, FEATURE_DOCS, FEATURE_DOCS_REVIEW, FEATURE_DOCS_STAGE, FEATURE_CI, FEATURE_CI_WRITE)
_ROLES = ("issue_writer", "docs_writer", "docs_reviewer", "ci_runner")


class RegistryShapeTests(unittest.TestCase):
    def test_every_family_has_a_handler_and_every_schema_is_closed(self):
        for spec in REGISTRY:
            with self.subTest(tool=spec.name):
                self.assertIn(spec.family, HANDLERS)
                self.assertIs(spec.input_schema.get("additionalProperties"), False)
                self.assertEqual(spec.definition["inputSchema"], spec.input_schema)

    def test_a_confirm_gated_tool_is_a_role_guarded_write(self):
        # `confirm` in the schema is the two-step gate (ADR-0003); a tool that
        # takes it must be one policy guards with a role, and every role-guarded
        # tool outside memory must be a write or a review, never a read.
        for spec in REGISTRY:
            with self.subTest(tool=spec.name):
                if "confirm" in spec.arguments:
                    self.assertNotEqual(spec.access, READ)
                    self.assertIsNotNone(spec.role)
                if spec.role is not None:
                    self.assertNotEqual(spec.access, READ)
                if spec.access != READ and spec.family != MEMORY:
                    self.assertIsNotNone(spec.role, "a write outside memory needs a role")

    def test_tool_definitions_lists_the_registry_in_order(self):
        self.assertEqual([t["name"] for t in tool_definitions()], [s.name for s in REGISTRY])
        self.assertEqual(len(SPECS_BY_NAME), len(REGISTRY))


class DiscoveryMatchesPolicyTests(unittest.TestCase):
    def test_nothing_advertised_is_denied_and_every_allowed_tool_is_advertised_when_its_features_are_on(self):
        # Every combination of roles, with and without an issue project, and
        # every combination of enabled features: what tools/list shows must be
        # exactly what policy allows among the tools whose features are on.
        policy = Policy()
        for role_count in range(len(_ROLES) + 1):
            for roles in itertools.combinations(_ROLES, role_count):
                for issue_project in (None, "97"):
                    principal = Principal(actor="a", project="p", roles=roles, token_id="t", issue_project=issue_project)
                    allowed = {s.name for s in REGISTRY if policy.decide(s.name, principal).allowed}
                    for feature_count in range(len(_FEATURES) + 1):
                        for features in itertools.combinations(_FEATURES, feature_count):
                            enabled = set(features)
                            shown = {s.name for s in visible_tools(principal, enabled)}
                            expected = {s.name for s in REGISTRY if s.name in allowed and s.requires <= enabled}
                            self.assertEqual(shown, expected, f"roles={roles} issue_project={issue_project} features={features}")

    def test_issue_tools_need_the_tenant_claim_before_the_role(self):
        principal = Principal(actor="a", project="p", roles=("issue_writer",), token_id="t")
        self.assertEqual(Policy().decide("issues.create", principal).reason, "token has no issue project")
        self.assertEqual({s.family for s in visible_tools(principal, set(_FEATURES))} & {ISSUES}, set())

    def test_an_unknown_tool_is_denied_before_anything_else_is_looked_up(self):
        principal = Principal(actor="a", project="p", roles=(), token_id="t")
        self.assertEqual(Policy().decide("issues.delete", principal).reason, "destructive operations are denied")
        self.assertEqual(Policy().decide("nope.tool", principal).reason, "tool is not allowed in phase1")


if __name__ == "__main__":
    unittest.main()
