# MCP Governance Gateway

A governance and multi-tenancy layer that sits between AI coding agents and the
backends they use — team memory, an issue tracker, a documentation corpus, and
CI — and exposes them over the [Model Context Protocol](https://modelcontextprotocol.io).

Agents get a small, uniform set of MCP tools. The gateway makes those tools
**safe to hand to an autonomous agent** in a team setting:

- **Per-tenant isolation.** Each token is bound server-side to one project. The
  tenant is never a tool argument, so an agent cannot read or write another
  team's memory or issues — the boundary is enforced by the gateway, not
  trusted from the client.
- **Confirmation-gated writes.** Mutating tools use a two-step prepare/commit
  flow. The first call returns a single-use, short-lived confirmation id bound
  to the exact arguments; nothing is written until a second call confirms it.
- **Per-user attribution and an audit trail.** Every call is logged with the
  acting identity; writes to a backend are stamped with who asked, so a shared
  service credential never erases individual accountability.
- **Least privilege, where roles exist.** Issue writes require an explicit
  `issue_writer` role (default-deny) and destructive operations are denied
  outright. Be aware of the boundary: memory writes are gated by tenancy and
  quota, not by a role, so a token with a project can append to that project's
  shared memory — [the security model states exactly which tools check
  what](docs/security-model.md#authorization-as-implemented).

The gateway is a single Python process (standard-library HTTP server, one third-
party dependency for encryption). Backends are pluggable and enabled by
configuration — run only the ones you need.

## Backends

| Capability | Tools | Backend |
|---|---|---|
| Team memory | `memory.search` / `save` / `list`, `memory.lesson_*`, `memory.action_*` | [agentmemory](https://github.com/rohitg00/agentmemory) (Apache-2.0) |
| Issue tracker | `issues.get` / `search` / `mine` / `categories` / `create` / `add_note` / `update_status` | Redmine **or** GitLab (per deployment) |
| Docs corpus | `docs.search` / `get` / `list` | per-project Git repositories, indexed with a built-in BM25 (CJK-aware) |
| CI | `ci.status` / `ci.log` / `ci.artifact` | Jenkins (read-only) |

Each backend enforces the same tenancy discipline: operations are scoped to the
token's project, results are re-filtered defensively, and errors never leak the
existence of another tenant's data.

## Security model in one paragraph

A bearer token carries no secrets in the string itself — it is an opaque handle
resolved server-side to a set of claims (`project`, `issue_project`, `actor`,
`roles`). Because the claims live on the server, renaming or re-scoping them
needs no token re-mint. Writes additionally require a writer role
(default-deny). Optional per-user credentials (a personal Redmine key or GitLab
PAT) are held in an encrypted-at-rest keystore (AES-256-GCM) with the ciphertext
bound to the owner and backend, so a credential cannot be replayed as another
user's or another backend's. See [`docs/security-model.md`](docs/security-model.md)
and the [architecture decision records](docs/decisions/).

## Quickstart

```bash
pip install .

# Minimal: memory backend only
export GATEWAY_TOKEN_FILE=/etc/mcp-governance-gateway/tokens.json   # project -> claims
export MEMORY_BASE_URL=http://127.0.0.1:3111
mcp-governance-gateway                              # serves MCP on :8080/mcp
```

Enable more backends by setting their environment variables (see
[`.env.example`](.env.example)):

- **Issues** — `ISSUE_BACKEND=redmine|gitlab` plus that backend's URL and token.
- **Docs corpus** — `DOCS_REPOS_FILE` (project → Git repo) and `DOCS_CLONE_DIR`.
- **CI** — `JENKINS_BASE_URL` and `CI_JOBS_FILE` (project → allowlisted jobs).

A token file entry looks like:

```json
{
  "tokens": [
    {
      "token": "<opaque-bearer>",
      "project": "demo-project",
      "issue_project": "demo",
      "actor": "10000001",
      "roles": ["issue_writer"]
    }
  ]
}
```

Run it in a container with the provided [`Dockerfile`](Dockerfile) (the image
includes `git` + `ssh` so the docs corpus can clone remote repositories).

## Configuration reference

All configuration is environment-driven; [`.env.example`](.env.example) lists
every variable with a comment. Nothing is enabled implicitly — a backend is
inert unless its variables are set.

## Ownership boundaries (optional)

`scripts/check_owners.py` enforces module ownership at commit time using the
[find-owners](https://gerrit.googlesource.com/plugins/find-owners/) format: a
change touching a path you do not own is rejected unless it carries a
`Cross-Owner:` trailer and the owner approves at review. It is standalone and
does not require the gateway. See [`scripts/README.md`](scripts/README.md).

## Documentation

| Document | What it covers |
|---|---|
| [Architecture](docs/architecture.md) | The planes, modules, request flow, and where identity comes from |
| [Security model](docs/security-model.md) | The trust boundaries and what each one assumes |
| [Operations](docs/operations.md) | Deployment shapes, token lifecycle, quotas, backend-isolation checklists |
| [ADRs](docs/decisions/) | Each decision, the alternatives weighed, and what enforces it |
| [Roadmap](docs/roadmap.md) | What is deliberately not here yet, and why |
| Adapters | [memory](docs/adapters/memory.md) · [issue tracker](docs/adapters/issue-tracker.md) · [docs corpus](docs/adapters/docs.md) · [CI](docs/adapters/ci.md) |

Start with [ADR-0001](docs/decisions/ADR-0001-mcp-governance-gateway.md) for what
the gateway is, then [ADR-0002](docs/decisions/ADR-0002-token-boundaries.md) and
[ADR-0003](docs/decisions/ADR-0003-confirmation-and-dangerous-actions.md) for the
two properties everything else preserves.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
