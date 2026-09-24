"""The footer stamped on what the gateway writes where people read it.

The two literals below are what every issue note, issue description and
review comment has carried since 0.1.0. They are spelled out rather than
built from `footer()` so a change to the stamp fails here, where it is a
visible decision, instead of passing because both sides moved together."""
import unittest

from mcp_governance_gateway.attribution import footer
from mcp_governance_gateway.issue_backend import _with_attribution
from mcp_governance_gateway.memory_backend import RequestContext
from mcp_governance_gateway.review_backend import stamped

_CTX = RequestContext(actor="10000001", project="p", client="t", request_id="req-42")
_FULL = "[via mcp-governance-gateway | actor=10000001 | audit=req-42]"
_TRIMMED = "[via mcp-governance-gateway | audit=req-42]"


class FooterTests(unittest.TestCase):
    def test_the_stamp_is_unchanged(self):
        self.assertEqual(footer(_CTX), _FULL)
        self.assertEqual(footer(_CTX, personal=True), _TRIMMED)

    def test_issue_framing_strips_the_body_and_stands_alone_when_empty(self):
        self.assertEqual(_with_attribution("  note  ", _CTX), f"note\n\n{_FULL}")
        self.assertEqual(_with_attribution("note", _CTX, personal=True), f"note\n\n{_TRIMMED}")
        self.assertEqual(_with_attribution(None, _CTX), _FULL)
        self.assertEqual(_with_attribution("   ", _CTX), _FULL)

    def test_review_framing_keeps_leading_whitespace_and_always_names_the_actor(self):
        self.assertEqual(stamped("  comment \n", _CTX), f"  comment\n\n{_FULL}")
        self.assertEqual(stamped("", _CTX), f"\n\n{_FULL}")


if __name__ == "__main__":
    unittest.main()
