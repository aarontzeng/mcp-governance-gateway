# Architecture

## Overview

The gateway is a policy and identity boundary between coding agents and the
backends they use.

```text
MCP host / agent  (per-user bearer token, ADR-0007)
  -> TLS ingress
  -> gateway  /mcp        authn / policy / confirmation / audit
  -> private backends     memory service, issue tracker,
                          per-project docs repos, CI (reads + gated rerun)
```

The gateway is the single enforcement point. That is safe because it enforces
independently: an optional front gateway can sit in front of it for SSO, but
nothing about the tool-call path depends on one being there (ADR-0004, amended by
ADR-0006).

## Protocol Shape

The public endpoint is a Streamable HTTP MCP endpoint:

```text
POST /mcp
```

`POST` is the whole MCP surface today. Streamable HTTP also defines `GET` (server
-initiated SSE) and `DELETE` (session termination); this gateway implements
neither, and both return 405 — request/response over POST is enough for the
lifecycle and tool calls, and a client written against the other two verbs would
be written against a gateway that does not exist yet.

The gateway supports the current MCP lifecycle and capability negotiation, and
advertises only the tools allowed for the authenticated actor and project.

Three route families exist outside `/mcp`, authenticated by the same bearer token and
deliberately not MCP tools:

| Route | Why not a tool |
|---|---|
| `PUT /docs/asset-stage/<upload-token>` | Uploads Markdown bytes outside agent context; bound to the minting actor, project and token, with the same signed identity propagation as `/mcp`. |
| `GET /ci/artifact` | Returns raw bytes. A build artifact is routinely tens of megabytes, which belongs on disk, not in an agent's context. |
| `/internal/*` | Credential enrollment: a user submits their own downstream key. Scoped strictly to the caller's own actor. **It must not be routed by a public ingress** — it accepts personal secrets, and its integration contract is not yet defined (see the roadmap). |

## Core Modules

| Module | Responsibility |
|---|---|
| Transport | MCP JSON-RPC over Streamable HTTP |
| Auth | Validate the per-user bearer token; derive actor, project, roles |
| Policy | Decide allow, deny, or require confirmation |
| Confirmation | Two-step prepare/commit, single-use and argument-bound |
| Registry | Build a role/project-specific tool list |
| Adapters | Translate stable tools into backend API calls and re-enforce write policy |
| Audit | Write structured event logs with redaction |
| Secrets | Hold downstream credentials server-side |
| Credential store | Per-user downstream keys, AES-256-GCM at rest, AAD-bound to the actor and backend (ADR-0009) |
| Secret scan | Reject credential-shaped values on team-visible, append-only writes |
| OIDC (optional) | Verify an IdP's access token, `sub` → actor; tenancy from a deployment-owned grants file (ADR-0016) |
| Docs corpus | Per-project git repo mirror: BM25 search, hot-reloaded config, author provenance (ADR-0011, ADR-0015) |
| Docs review | Proposals as pull requests under the caller's own credential; seven operations and no way to merge one (ADR-0017) |
| CI adapter | Status, build history, log tail and artifact listing behind a server-side project→jobs allowlist; `ci.rerun` behind a second, narrower trigger allowlist plus a role and the confirmation gate |

## Request Flow

1. The client sends an MCP request to `/mcp` through the TLS ingress.
2. The gateway validates transport headers and the bearer token.
3. It derives `actor`, `project`, `issue_project` and roles **from the token** —
   identity is the token itself (ADR-0007), never a client-supplied header.
4. It validates the JSON-RPC method and the tool's input schema.
5. Policy returns `allow`, `deny`, or `require_confirmation` (default-deny;
   destructive operations are denied outright).
6. Where confirmation is required, the two-step prepare/commit flow runs: a
   single-use confirmation bound to actor, tool, and the exact arguments.
7. The gateway injects the tenant and calls the backend with server-held
   credentials — or, for authorship writes, the caller's own encrypted key
   (ADR-0009).
8. It normalizes the response and records the audit event (actor, project, tool,
   outcome, request id).

## Identity

**The token is the identity.** Each token resolves server-side to a set of
claims — `project`, `issue_project`, `actor`, `roles` — so the tenant is never a
tool argument and cannot be supplied by a client. Because the claims live on the
server, re-scoping a token needs no re-mint.

Tokens are provisioned out of band, by whatever the deployment already uses for
identity: an operator-managed token file, or a minting service that writes one.
The gateway reads a static file plus an optional runtime-managed one, hot-reloads
both on change, and treats each entry as individually revocable. What mints them
is outside this project.

Two things are optional and inert unless configured:

- **Signed identity propagation.** A front gateway that has authenticated an
  end-user may forward that identity as headers with an HMAC signature over the
  payload. Without a shared secret the headers are ignored entirely, so a forged
  header cannot take effect; with one, only the signed fields are trusted
  (ADR-0004, ADR-0006).
- **Per-user downstream credentials.** A user may enroll their own issue-tracker
  key so writes carry their name rather than a shared service account's
  (ADR-0009).

## Backend Isolation

Backends are not public MCP endpoints. They are private services reachable by the
gateway process or gateway network only. Once a backend is fronted by the
gateway, direct user or agent paths to it must be closed.

Clients reach the **gateway** through the TLS ingress; they must never reach the
**backends**. The backends do not enforce tenant isolation themselves — project
and actor metadata are injected by the gateway — so a direct backend connection
would bypass policy, audit, and namespace checks entirely.

Operational requirements:

- Backend listeners bind to loopback or a private service network; only the
  ingress route to the gateway is public.
- Backend secrets are not distributed to MCP clients.
- Backend secrets are rotated after migrating away from direct access.
- No client configuration should include direct backend URLs for normal use.

## Context Model

Minimum context attached to every tool call:

```json
{
  "requestId": "req_...",
  "actor": {
    "id": "E1000001",
    "emailLabel": "user@example.com",
    "roles": ["developer"]
  },
  "project": {
    "id": "example-project",
    "issueProject": "97"
  },
  "client": {
    "name": "codex",
    "version": "unknown"
  }
}
```

The actor key is an immutable id (ADR-0007); the email is a display label.
Human-facing surfaces map the id to a readable name.

## Deployment and Availability

The gateway can run next to its memory backend for a small deployment, with
nginx or another ingress providing TLS and routing. The gateway remains the
identity and policy boundary; ingress alone is not enough.

Gateway unavailability must fail closed:

- Agents cannot call backend tools through the gateway.
- Agents do not fall back to direct backend credentials.
- Write operations remain unavailable until the gateway returns.

That makes the gateway a single point of failure for agent tooling, so a
production rollout needs explicit availability work:

- health checks for transport, policy, adapters, audit, and the secret store
- backup and restore for policy, audit, and secret state
- a runbook for token revocation and backend secret rotation
- optional active/passive or replicated instances
- a maintenance mode that disables writes while keeping reads visible
