# ADR-0002: Do Not Pass Through Client Tokens

## Status

Accepted

## Date

2026-06-23

## Context

The Gateway receives credentials from MCP clients and then calls downstream
services. Passing the incoming client token directly to downstream services
creates confused-deputy and audience-boundary problems.

## Decision

The Gateway validates inbound tokens for itself and never forwards those tokens
to downstream services. It uses separately managed downstream credentials.

## Consequences

- Gateway tokens must be audience-bound to the Gateway.
- Downstream secrets must be stored and rotated by the Gateway.
- Audit must correlate inbound actor identity with downstream calls.
- Pilot gateway tokens are revocable, scoped credentials with no direct backend
  authority.
- Initial issue tracker writes use a controlled service account plus actor and
  audit metadata.
- Per-user downstream writes require user credential delegation or token
  exchange after SSO and secret-store hardening.
