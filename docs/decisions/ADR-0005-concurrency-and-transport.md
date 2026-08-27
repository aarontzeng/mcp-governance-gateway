# ADR-0005: Concurrency Model and Streamable HTTP Transport

## Status

Accepted

## Date

2026-06-24

## Context

Phase 1 implements the `/mcp` endpoint with the Python standard library
`ThreadingHTTPServer` (synchronous, thread-per-request, blocking `urllib` for
backend calls) and returns a single JSON-RPC response per POST. It has no SSE
stream, no session management, and no third-party dependencies.

The pilot workload is I/O-bound and small: a handful of engineers and agents,
single-digit requests per second at peak. Throughput is not the constraint; the
backends (memory, issue tracker) dominate latency. A larger team (10-15 people)
stays in the same order of magnitude and does not change this.

The relevant constraint is the streaming nature of MCP. The Streamable HTTP
transport uses Server-Sent Events for server-to-client messages. In particular,
MCP elicitation (ADR-0003) requires the server to send a request to the client
mid-tool-call, which needs an SSE response channel. A request/response, JSON-only
server cannot perform that interaction.

## Decision

Phase 1 uses the synchronous standard-library HTTP server with single JSON
responses and zero third-party dependencies. This keeps the security-critical
core small, dependency-free, and easy to audit.

Migrate to an asynchronous ASGI stack (for example Starlette + httpx + uvicorn)
when, and only when, a concrete trigger below is reached. The migration is an
explicit decision, not a default to drift into.

### Triggers to revisit (any one)

- Need real MCP elicitation or any server-initiated message to clients (requires
  SSE).
- Need to stream long-running tool results or progress notifications.
- A measured limit in the gateway itself: thread-per-request plus blocking I/O
  causes thread pile-up under slow backends, or the gateway adds material p99
  latency of its own.
- Production hardening needs that exceed `BaseHTTPRequestHandler` (graceful
  shutdown, connection limits, robust HTTP edge cases).

## Alternatives Considered

### Start on ASGI (Starlette + httpx + uvicorn) from Phase 1

- Pros: native SSE and elicitation, production-grade server, no later
  synchronous-to-asynchronous migration.
- Cons: adds dependencies and asynchronous complexity before they are needed;
  works against simplicity-first for the pilot.
- Deferred: revisit when a trigger above is reached.

### Hand-rolled asyncio without a framework

- Pros: keeps zero dependencies.
- Cons: hand-writing HTTP and SSE is error-prone; if going asynchronous, the ASGI
  ecosystem is the better foundation.
- Rejected.

### Rewrite in another language for performance (e.g. Rust)

- Pros: single static binary, lower footprint.
- Cons: performance is not the bottleneck at this scale, and a memory-safe
  language gives no safety gain over Python; doubling the implementation is not
  justified by the current workload.
- Rejected for now; would be driven by a distribution or org-standard reason, not
  by this service's load.

## Consequences

- Phase 1 stays zero-dependency and simple.
- Until migration, MCP elicitation is unavailable through the gateway; all
  confirmation uses the prepare/commit fallback from ADR-0003. This is an
  accepted limitation, not a defect.
- Keep the HTTP handler and backend client thin and isolated; they are the
  asynchronous surface, and a small surface keeps the eventual migration cheap.
- Prefer migrating at Phase 2/3, before more adapters accrete, if elicitation or
  SSE is wanted — the synchronous-to-asynchronous ("colored function") cost grows
  with the I/O surface.
