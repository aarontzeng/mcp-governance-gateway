# Memory Adapter

The memory adapter exposes project-scoped persistent memory tools over a backend
memory service.

## Tool Surface

| Tool | Operation | Description |
|---|---|---|
| `memory.search` | read | Search memories visible to the project |
| `memory.save` | write | Save a new memory with project scoping and gateway audit attribution |
| `memory.list` | read | List the project's memories (newest first), paginated, for review/reports |
| `memory.lesson_save` | write | Save a project-scoped lesson (a persistent "never do this again" rule); `{rule, reason?, confidence?}` folded into the backend `content` |
| `memory.lesson_list` | read | List the project's lessons, highest confidence first — the cap keeps the most reinforced rules rather than an arbitrary backend prefix |
| `memory.action_create` | write | Create a project-scoped follow-up action (`{title, description?, priority?}`); status starts `pending` |
| `memory.action_list` | read | List the project's **open** actions (pending/active/blocked) — the live board. `includeDone:true` adds completed ones, for reports. Done is filtered out *before* the limit window, so a finished action cannot crowd out an open one |
| `memory.action_update_status` | write | Advance an action `pending→active→done/blocked` via `POST /agentmemory/actions/update {actionId, status}`; the target is project-pre-checked (a cross-project id → 404) and `status` is enum-validated server-side |

All memory writes are **secret-scanned server-side** before the quota check: text
matching a high-precision credential pattern (a PEM private key, an AWS/GitHub/
GitLab/Slack/Google/`sk-`-style token, a JWT, a bearer blob, a `key=value`
credential assignment) is rejected with a clear error. These stores are
append-only and team-visible, so an agent that writes a credential here cannot
take it back — the check exists because guidance alone is advice to a model.
Patterns anchor on a value-shaped blob, never a keyword: `api_key=<from-env>` and
a bare variable name do not trip it.

Search results are unwrapped to the flat schema documented below. The backend
returns each hit as `{observation, score}`; the relevance score is carried onto
the normalized record rather than lost with the wrapper.

Lessons and actions are project-scoped and isolated exactly like memories (the
gateway injects the token's `project`; the client cannot override it). The
knowledge **graph** and **crystals** (action digests) are derived server-side by
the backend LLM — the adapter exposes **no** tool to write them, so agents never
mutate them; they are admin-viewer-only overviews. The LLM-driven backend features
(graph/crystals/consolidation) require a clean-JSON, non-reasoning model
(`gemini-2.5-flash`); a `<thought>`-emitting model yields empty extractions.

## Metadata Contract

Phase 1 targets agentmemory's current REST contract. The backend memory record
stores the gateway-controlled project value in the native `project` field:

```json
{
  "project": "example-project"
}
```

Actor attribution is kept in the gateway audit log (authoritative). In addition,
`memory.save` stamps an `actor:<actor>` concept onto the stored record (the
`/remember` API has no actor field) so the viewer and `memory.list` can attribute
and group memories by contributor. Every write audit event must include:

```json
{
  "actor": "user@example.com",
  "project": "example-project",
  "requestId": "req_...",
  "tool": "memory.save"
}
```

Do not depend on clients to submit actor, project, or source metadata. The
adapter derives project from the authenticated gateway token or front-gateway
assertion and derives actor from the same trusted identity boundary.

## Project Isolation

agentmemory 0.9.27 filters `memory.search` by the `project` field server-side,
and its result items carry no project field of their own. The gateway therefore:

- always injects the authenticated token's project into the search request (the
  client cannot override it), so results are scoped to the caller's project
- returns only the result list in a gateway-built envelope; the raw backend body
  (aggregate `tokens_used`/`truncated`/etc.) is never spread through, and a
  non-list `results` shape fails closed to an empty result
- keeps backend service secrets server-side

Tenant isolation for search thus rests on the gateway-controlled `project` plus
agentmemory's server-side filter — acceptable for a trusted internal backend the
gateway already holds the secret for.

`memory.list` returns the project's memories (newest first, paginated) for review
and report-building. agentmemory's `/agentmemory/memories` endpoint does **not**
honor a `project` query parameter (verified — it returns every project), but each
returned item **does** carry a `project` field. The gateway therefore fetches a
bounded window, filters to the caller's project itself (dropping any other
project's items — the server-side filter is not trusted), sorts newest-first, and
paginates. The bounded fetch caps memory use; a `truncated` flag signals when a
project may hold more than the fetch cap.

## Write Limits

The gateway rejects excessive `memory.save` calls before sending them to
agentmemory:

- oversized `text` payloads
- per-user per-project writes above the minute threshold
- per-project writes above the daily threshold

These limits are a pilot safety guard, not billing-grade quota accounting. The
Phase 1 counters are process-local and reset on restart.

## Backend Access

The memory backend must not remain directly reachable by normal MCP clients
after the gateway is enabled. Otherwise a client can bypass gateway-injected
project metadata, RBAC, and audit logging.

Deployment requirements:

- Bind backend ports to loopback or a private network.
- Permit backend API calls from the gateway path only.
- Retire direct user SSH tunnel instructions for normal memory access.
- Rotate backend credentials after migration.
- Keep any viewer/admin endpoint separate from the agent-facing MCP path.

## Graph and LLM Features

The MVP should not depend on graph extraction or external LLM enrichment. Basic
embedding-backed search is sufficient for the first rollout.
