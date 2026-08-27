# ADR-0001: MCP Governance Gateway

## Status

Accepted

## Date

2026-06-23

## Context

Engineering agents need controlled access to internal tools such as issue
tracking, memory, CI, and documentation. Directly configuring every backend MCP
server in every agent creates inconsistent authentication, scattered secrets,
and weak auditability.

## Decision

Build a governance MCP gateway that exposes one authenticated MCP endpoint and
proxies approved tools to backend adapters.

## Alternatives Considered

### Existing MCP gateway or proxy

- Pros: Could reduce implementation and maintenance cost.
- Cons: Must be evaluated against the required identity, project RBAC, audit,
  secret custody, and confirmation semantics before adoption.
- Decision: Keep build-vs-buy as a Phase 0 gate. The design proceeds with a
  small internal implementation plan, but implementation should not skip this
  review.

### Commit backend MCP config to each repo

- Pros: Simple.
- Cons: Duplicates config, distributes secrets, and does not centralize policy.
- Rejected.

### Nginx reverse proxy only

- Pros: Quickly removes SSH tunnels and can provide TLS.
- Cons: Does not provide per-user tool identity or project RBAC.
- Rejected as the final architecture; acceptable as ingress only.

### MCP Governance Gateway

- Pros: Central identity, policy, audit, and secret custody.
- Cons: More implementation work.
- Accepted.

## Consequences

- Agents connect to one Gateway endpoint.
- Backend credentials remain server-side.
- Tool rollout can be staged by project and role.
- Gateway becomes a security-critical service and needs explicit hardening.
- Gateway unavailability fails closed; agents must not fall back to direct
  backend credentials.
