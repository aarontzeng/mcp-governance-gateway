# ADR-0004: Keep Domain Security in an Independent Server

## Status

Accepted — amended by ADR-0006: a front gateway is no longer on the tool-call
data plane. The independence this ADR mandated is what made that change cheap.

## Date

2026-06-23

## Context

A front gateway can sit in front of MCP clients — [ContextForge][cf] is one such
product — providing control-plane capabilities: SSO, token scoping, a tool
registry, unified endpoints, observability, operational management.

[cf]: https://github.com/IBM/mcp-context-forge

Domain-specific security behaviour still has to hold, and has to keep holding
across gateway choices:

- actor and project injection
- default-deny and deny-overrides policy
- destructive operation denial
- prepare/commit confirmation fallback
- issue-tracker and CI service-account attribution
- memory tenant filtering
- domain audit schema

These controls are security-critical. Implementing them as front-gateway plugins
or passthrough configuration would couple them to that platform's plugin API and
data model.

## Decision

A front gateway, where one is adopted, is the front control plane. This gateway
stays a separate MCP server behind it.

This gateway owns domain-specific authorization, tenant injection, confirmation
and audit. A front gateway may do its own RBAC and tool filtering, but this one
independently re-enforces write policy and destructive-deny regardless.

This gateway must not trust plaintext identity headers from arbitrary clients. It
accepts actor/project identity only when the request arrives through the trusted
path or carries a signed assertion it verifies itself.

## Alternatives Considered

### Put all policy in front-gateway plugins

- Pros: Fewer runtime components and simpler topology.
- Cons: Couples core security behaviour to one platform's plugin API and runtime
  behaviour; harder to test independently; harder to migrate off.
- Rejected for security-critical domain policy.

### Expose backends directly through front-gateway passthrough

- Pros: Fastest setup.
- Cons: Cannot safely inject actor/project metadata, enforce domain-specific
  write policy, or guarantee service-account attribution without custom logic.
- Rejected for issue-tracker, CI, and memory writes.

### This gateway only, no front gateway

- Pros: Smallest trusted computing base.
- Cons: SSO, registry, token lifecycle and observability must be built or
  integrated separately.
- Kept as a supported mode — and it is what ADR-0006 settled on.

## Consequences

- This gateway is the minimum viable core and is built first.
- Adopting a front gateway is an integration decision, not a hard dependency.
- Behind a front gateway, this gateway is deployed on a private path reachable
  only by it.
- The front-gateway identity contract is explicitly tested.
- Write policy is enforced twice where a front gateway exists: once there, and
  again here.
