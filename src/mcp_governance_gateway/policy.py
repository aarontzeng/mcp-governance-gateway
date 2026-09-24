"""Allow, deny, or (elsewhere) require confirmation: the per-call decision.

A project-scoped, exact-match allow-list read from the tool registry. Memory
tools are allowed for any token that carries a project; issue tools
additionally require an issue_project (the tenant boundary for the tracker);
a write names the role it needs and a token without it is refused. Roles
beyond the four the registry names are carried on the Principal and not
interpreted -- general RBAC is still deferred. Everything else is denied, and
destructive operations are always denied, by name, before the registry is
consulted (ADR-0003).

The registry is the only source of what exists: a tool policy allows is one
discovery can advertise and dispatch can run, because all three read the
same record.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .auth import Principal
from .tools import SPECS_BY_NAME, ToolSpec
from .tools.base import CI, DOCS, ISSUES, MEMORY, READ, REVIEW, WRITE

_DESTRUCTIVE_SUFFIXES = ("delete", "destroy", "purge", "remove")

# The reasons an audit line carries. The "phase1" wording is what every log
# line has said since 0.1.0; a grep over an audit history still finds it.
_ALLOW_REASON: Mapping[tuple[str, str], str] = {
    (MEMORY, READ): "phase1 memory tool",
    (MEMORY, WRITE): "phase1 memory tool",
    (ISSUES, READ): "phase1 issue read",
    (ISSUES, WRITE): "phase1 issue write",
    (DOCS, READ): "docs read",
    (DOCS, WRITE): "docs propose",
    (DOCS, REVIEW): "docs review comment",
    (CI, READ): "ci read",
    (CI, WRITE): "ci run",
}
_MISSING_ROLE_REASON: Mapping[str, str] = {
    "issue_writer": "token lacks issue write role",
    "docs_writer": "token lacks docs write role",
    "docs_reviewer": "token lacks docs review role",
    "ci_runner": "token lacks ci run role",
}


@dataclass(frozen=True)
class PolicyDecision:
    decision: str
    reason: str

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


class Policy:
    def __init__(self, specs: Mapping[str, ToolSpec] | None = None) -> None:
        self._specs = specs if specs is not None else SPECS_BY_NAME

    def decide(self, tool_name: str, principal: Principal) -> PolicyDecision:
        if not principal.project:
            return PolicyDecision("deny", "missing project")
        if tool_name.split(".")[-1] in _DESTRUCTIVE_SUFFIXES:
            return PolicyDecision("deny", "destructive operations are denied")
        spec = self._specs.get(tool_name)
        if spec is None:
            return PolicyDecision("deny", "tool is not allowed in phase1")
        if spec.family == ISSUES and not principal.issue_project:
            return PolicyDecision("deny", "token has no issue project")
        if spec.role is not None and spec.role not in principal.roles:
            return PolicyDecision("deny", _MISSING_ROLE_REASON.get(spec.role, f"token lacks the {spec.role} role"))
        return PolicyDecision("allow", _ALLOW_REASON[(spec.family, spec.access)])
