"""What a tool is, and what a tool handler may ask of the gateway.

A `ToolSpec` is the one record of a tool: its MCP definition, which backend
family serves it, whether it reads or writes, the role a write needs, and the
deployment features `tools/list` must see enabled before advertising it.
Policy, discovery, argument validation and dispatch all read from the same
record, so a tool cannot be allowed by one and unknown to another -- which is
what happened when each of those kept its own set of names.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Protocol

if TYPE_CHECKING:
    from ..auth import Principal
    from ..ci_backend import JenkinsHttpBackend
    from ..docs_assets import AssetStage
    from ..docs_backend import DocsCorpus
    from ..docs_review import DocsReviewService
    from ..issue_backend import IssueBackend
    from ..limits import MemoryWriteLimiter
    from ..memory_backend import MemoryBackend, RequestContext

# Backend families. Tenancy for each is enforced differently (see policy.py),
# which is why the family is a field rather than a prefix parsed off the name.
MEMORY = "memory"
ISSUES = "issues"
DOCS = "docs"
CI = "ci"

# What a tool does to the system of record behind it.
READ = "read"
WRITE = "write"       # proposes or commits something; role-guarded, usually confirm-gated
REVIEW = "review"     # an opinion on someone else's proposal; its own role (docs only)

# Roles a principal may carry. Default-deny: a write tool names one, and a
# token without it is refused whatever else it holds.
ISSUE_WRITER = "issue_writer"
DOCS_WRITER = "docs_writer"
DOCS_REVIEWER = "docs_reviewer"
CI_RUNNER = "ci_runner"

# Deployment features `tools/list` checks before advertising a tool. Discovery
# is not a security boundary -- policy re-checks every call -- but a tool that
# cannot succeed should not be offered.
FEATURE_ISSUES = "issues"
FEATURE_DOCS = "docs"
FEATURE_DOCS_REVIEW = "docs_review"
FEATURE_DOCS_STAGE = "docs_stage"
FEATURE_CI = "ci"
FEATURE_CI_WRITE = "ci_write"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    family: str
    access: str = READ
    role: str | None = None
    requires: frozenset[str] = field(default_factory=frozenset)
    # The audit's handle on what a write created, when it is not the result's
    # `id` or `queueItem`.
    resource_id: Callable[[dict[str, Any]], str | None] | None = None

    @property
    def definition(self) -> dict[str, Any]:
        """The tool as `tools/list` advertises it."""
        return {"name": self.name, "description": self.description, "inputSchema": self.input_schema}

    @property
    def arguments(self) -> frozenset[str]:
        """The argument names the schema declares. Every schema says
        `additionalProperties: false`; dispatch enforces it from this."""
        return frozenset(self.input_schema.get("properties", {}))


class ToolHost(Protocol):
    """The gateway as a tool handler sees it: the configured backends, the two
    cross-cutting gates, and nothing else -- not the audit sink, not the
    policy. A handler decides what to call; the host decides whether."""

    memory_backend: MemoryBackend
    issue_backend: IssueBackend | None
    docs_corpus: DocsCorpus | None
    docs_review: DocsReviewService | None
    asset_stage: AssetStage | None
    ci_backend: JenkinsHttpBackend | None
    write_limiter: MemoryWriteLimiter

    def confirmation_gate(
        self, name: str, semantic: dict[str, Any], arguments: dict[str, Any], principal: Principal, summary: str,
    ) -> dict[str, Any] | None: ...

    def enforce_read_quota(self, principal: Principal) -> None: ...


ToolHandler = Callable[[ToolHost, str, dict[str, Any], "Principal", "RequestContext"], dict[str, Any]]
