# ADR-0006: The Tool-Call Data Plane Is Direct

## Status

Accepted — amends ADR-0004's "a front gateway is the front control plane"

## Date

2026-07-02

## Context

ADR-0004 kept domain security in this server so that a front gateway would be an
integration choice rather than a dependency. Having built that, the question is
whether a front gateway should carry the tool calls themselves.

Running one in front means two policy surfaces on the same request. The second
one adds no domain guarantee — per ADR-0004 this gateway independently
re-enforces every write policy and destructive-deny regardless of what precedes
it — while it does add a hop, a second place for identity to be reshaped in
transit, and an upgrade of someone else's software that can take the tool path
down.

Front gateways also tend to assume they can address themselves and their
upstreams by name. A deployment without DNS, or one where the container's view
of its own base URL differs from a client's, can make that assumption
unsatisfiable in both directions at once.

## Decision

Clients connect **directly** to this gateway's Streamable HTTP endpoint through
the TLS ingress, authenticated by per-user bearer tokens (ADR-0007).

A front gateway remains supported for what it is good at — SSO, a registry,
observability — and may forward a signed identity assertion (ADR-0004), but it is
not on the tool-call path and nothing in that path requires one.

## Alternatives Considered

### Front gateway on the data plane

- Pros: one architecture for both control and data; the registry sees every call.
- Cons: a second policy surface with no additional domain guarantee; a hop; a
  third party's release cadence on the critical path.
- Rejected for the tool path; kept for the control plane.

### Both data planes, front-gated and direct

- Pros: gradual migration.
- Cons: two public tool endpoints to secure, audit and explain, and config drift
  between them.
- Rejected.

## Consequences

- This gateway is the **single enforcement point** on the tool path. That is
  acceptable only because ADR-0004 made it independently enforcing from the
  start.
- Identity arrives as the token itself, not as forwarded headers. The
  identity-assertion machinery of ADR-0004 applies only where a front gateway is
  actually deployed.
- A front gateway's upgrades no longer risk the tool path.
- Whatever mints tokens becomes operationally critical instead — see ADR-0007.
