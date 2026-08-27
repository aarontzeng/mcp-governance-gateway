# ADR-0003: Confirmation and Dangerous Actions

## Status

Accepted

## Date

2026-06-23

## Context

Some tools can modify internal systems. The gateway can decide that a write
requires user confirmation, but the gateway has no UI of its own. Confirmation
therefore depends on an MCP client or host presenting the request honestly.

MCP 2025-06-18 includes elicitation, which lets a server request additional
user input through a client that advertises the elicitation capability.

## Decision

Use MCP elicitation as the preferred confirmation mechanism for confirmation-
eligible writes. For clients without elicitation support, use a two-step
prepare/commit tool contract.

Confirmation is not an authorization boundary. It prevents accidental writes by
honest clients; it does not protect against malicious clients. Destructive
operations are denied in the MVP instead of being protected by confirmation.

Elicitation prompts must not ask for secrets, passwords, API keys, raw tokens, or
other sensitive values.

## Consequences

- Policy must classify operations as read, write, or destructive.
- Only non-destructive writes can be confirmation-eligible.
- Confirmation ids must be short-lived and bound to actor, project, tool,
  target resource, normalized arguments, and request id.
- Clients without elicitation can still operate through prepare/commit tools.
- Truly dangerous operations need a separate product and security review before
  they can be enabled.
