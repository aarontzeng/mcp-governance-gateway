# Operations

## MVP Deployment

The MVP can run as a small internal service behind an HTTPS ingress. The ingress
handles TLS and routing; the gateway handles identity, policy, audit, and
backend credentials.

The gateway process itself serves plain HTTP. Bind it to loopback or a private
service network and terminate TLS at the internal ingress. Do not expose the
gateway's HTTP port directly to user networks or the Internet, because bearer
tokens would otherwise be visible on the wire.

A worked example: nginx terminating TLS on `:443` and reverse-proxying to the
loopback gateway, with clients trusting whatever CA the deployment already uses
(a self-signed one is fine to start, and swappable later).

Two deployment shapes are supported. The gateway owns domain policy, tenant and
actor injection, and audit in both.

Gateway-only: the gateway is the front and exposes `/mcp` directly.

```text
MCP clients
  -> HTTPS ingress
  -> this gateway   (exposes /mcp; owns policy, injection, audit)
  -> private backends
```

Front-gateway mode: another gateway sits in front and adds SSO, RBAC, a tool
registry or observability, and this gateway becomes private behind it. Nothing
about the tool-call path depends on that being there — this gateway enforces
independently either way (ADR-0004, ADR-0006).

```text
MCP clients
  -> HTTPS ingress
  -> front gateway  (SSO / RBAC / registry / observability)
  -> this gateway   (private; owns policy, injection, audit)
  -> private backends
```

Backends must be reachable only from this gateway. Normal MCP clients must not
keep direct backend routes after migrating, and in front-gateway mode must never
reach this gateway directly.

## Gateway Token Lifecycle

Tokens are opaque handles minted outside this project. Whatever mints them, they
must be:

- unique per user
- scoped to project and role
- audience-bound to the gateway endpoint
- revocable server-side
- short-lived or rotated on a defined schedule
- stored outside project repositories

Rotation must not require changing backend issue tracker or memory credentials.

What the token model does and does not give you. Tokens are opaque values
matched server-side against a file, so the claims can be re-scoped without
re-minting anything. The token string is a bearer secret all the same: it
encodes nothing, but anyone holding it acts as that principal, so it is
handled like a password (never logged, never pasted into transcripts).
Token files are watched by `(mtime, size, inode)` and reloaded on change, so a
mint or a revoke takes effect without a restart — keyed on inode as well as
mtime because an atomic write swaps the inode, and two writes in the same
coarse-mtime tick would otherwise be indistinguishable, leaving a revoked token
authenticating. What is **not** here: there is no `aud`/`exp` claim validation,
because there are no claims in the string to validate. If you need
audience-binding or expiry, that belongs in whatever mints the tokens, and
plausibly in an OIDC front gateway rather than in this file.

## Credential Enrollment

A caller may enroll a **personal downstream credential** (a Redmine API key, a
GitLab PAT) so that writes go out under their own identity rather than under the
gateway's shared service account. The gateway exposes the API a page would call;
it does not ship the page (ADR-0007, and `docs/roadmap.md`).

| Route | Method | Does |
|---|---|---|
| `/internal/credentials` (alias: `/internal/redmine-key`) | GET | enrollment status for the bearer's own actor |
| | POST `{"key": "..."}` | verify the credential downstream, then store it encrypted |
| | DELETE | remove it |
| `/internal/my-issues` | GET | the caller's own open issues, using their enrolled credential |

### The contract

**This surface must not be routed publicly.** Set `ADMIN_PORT` (and, if
you must, `ADMIN_HOST` — it defaults to loopback) and it moves to its own
socket; the MCP listener then answers `404` for these paths, so an ingress that
publishes `/mcp` cannot publish enrollment with it. Leave `ADMIN_PORT` unset and
they stay on the MCP listener, which is the 0.1.0 behaviour and is only safe if
your ingress refuses `/internal/*` itself.

**It acts on the bearer's own actor and nothing else.** There is no "enroll for
user X" parameter, and the signed identity headers of ADR-0004 are deliberately
**not** applied here — a forged `X-Forwarded-User` can change who a `/mcp` call
is attributed to, and it must not be able to change whose credential is written.

**A credential is bound to the actor and the backend** by AES-GCM associated
data, so a stored record cannot be replayed as another person's or another
backend's even by someone who can edit the store file.

**Enrollment is gated on an email match.** The submitted credential is used to
ask the downstream tracker who it belongs to, and that account's email must
equal the `email` on the caller's gateway token. Two consequences an operator
must plan for:

- **A token minted without an `email` can never enroll.** The comparison needs
  both sides; the gateway refuses rather than guessing. Mint tokens with the
  address the tracker knows (`mcpgw-admin mint --email ...`), or expect every
  enrollment to fail with `identity_mismatch`.
- **When someone's email changes**, their existing stored credential keeps
  working — the record is keyed on the actor, which does not change — but they
  cannot *re-enroll* until the gateway token carries the new address. Update the
  token (`mcpgw-admin` writes the runtime store; a static entry is an edit) and
  the tracker account together. This is the one place email is load-bearing
  rather than a label, and it is a deliberate trade: an address is the only
  thing both systems can be asked about.

### Offboarding

In this order, so no window leaves a live credential without a live audit trail:

1. `DELETE /internal/credentials` as that user, **or** clear their record from
   the credential store — the encrypted key is the thing that still works after
   their gateway token is gone.
2. Revoke the gateway token: `mcpgw-admin revoke --actor <id> --project <p>`, or
   remove the entry from the static store. The gateway reloads on file change;
   a corrupt file keeps the last-good set and says so on stderr, so **confirm
   the revocation took effect** rather than assuming it.
3. With OIDC, remove the subject (or their group) from `OIDC_GRANTS_FILE` as
   well. Removing them at the IdP is necessary but not sufficient if a valid
   token is already in flight: it stays valid until it expires.
4. Their audit history stays. It names an actor id, not a person, and it is the
   record of what the gateway decided.

## Memory Capacity Controls

Infrastructure monitoring and gateway policy serve different purposes:

- infrastructure monitoring watches disk, Docker volume size, and container
  health
- the gateway enforces actor/project-aware read and write limits before the
  backend is touched

Process-local rate guards on the memory tools:

| Setting | Default | Purpose |
|---|---:|---|
| `MEMORY_SAVE_MAX_TEXT_BYTES` | `32768` | Reject oversized single memories before storage |
| `MEMORY_USER_WRITES_PER_MINUTE` | `30` | Limit accidental or runaway writes from one actor in one project |
| `MEMORY_PROJECT_WRITES_PER_DAY` | `5000` | Limit aggregate daily growth for one project |
| `MEMORY_USER_READS_PER_MINUTE` | `120` | Limit `memory.search` read floods |

Set a guard to `0` only for controlled tests. These counters live in process
memory, so they reset on restart and are **not** safe across replicas: running
more than one instance would multiply every quota by the instance count. A
multi-replica deployment needs quota state in a shared store first.

Host-side monitoring should alert on:

- memory-backend storage growth crossing whatever two thresholds give you a
  warning and then an alarm for your disk
- filesystem free space crossing the same two
- backend container health not `healthy`
- the memory backend's liveness endpoint failing

## Backend Isolation Checklist

For each backend, verify:

- direct client access to the backend is blocked
- in front-gateway mode, direct client access to this gateway is blocked (in
  gateway-only mode it is the authenticated front, reached through ingress)
- backend secrets are unavailable to clients
- backend secrets were rotated after direct-access migration
- gateway audit includes actor, project, tool, resource, and policy decision
- backend writes include actor and gateway audit id when native attribution uses
  a service account

## Tenant Isolation: agentmemory no-project records are global

agentmemory's `/search` project filter returns records that have **no project
field** regardless of the requested project — they behave as global and are
visible to every tenant. Records written **through the gateway** always carry the
token's project and are correctly isolated: same-project tokens share memory,
different-project tokens cannot see each other, and the audit trail attributes
each request to the right actor. The leak vector is any write that **bypasses the
gateway** and therefore sets no project — a direct bring-up test against the
backend is the usual way one appears.

The gateway cannot fix this on its own: agentmemory `/search` results do not
include a project field, so the gateway has nothing to post-filter on and must
trust the backend filter. Controls:

- **Required:** allow writes to the memory backend only through the gateway. Bind
  the backend to loopback or a private network and keep its token gateway-only,
  so no client can write a no-project (global) record.
- **Data hygiene:** purge any pre-existing no-project records with
  `POST /agentmemory/forget` and body `{"memoryId": "<id>"}`.
- **Defense-in-depth (backend change, tracked as a finding):** have agentmemory
  exclude no-project records from project-scoped `/search`, or return the project
  on each result so the gateway can drop mismatches.

## Front-Gateway Checklist

This applies only when another gateway sits in front of this one — for SSO, say.
In gateway-only mode this gateway is the authenticated front and serves `/mcp`
through ingress, so none of it applies. With a front gateway, verify:

- ingress strips external `x-user-id`, `x-tenant-id`, `x-project-id`, and
  equivalent identity headers
- this gateway accepts requests only from loopback, a private service network, mTLS,
  or another authenticated gateway path
- it rejects a request that contains forged identity headers from a normal
  client source
- it rejects missing, expired, wrong-audience, replayed, or invalid signed
  identity assertions when assertions are enabled
- it logs the front gateway's request id and its own decision id for correlation
- it independently denies destructive operations even when the front
  gateway exposes or forwards such a tool by mistake
- its write tools fail closed when policy, audit, or assertion validation is
  unhealthy

## Availability

The gateway is a single point of failure for agent tooling. That is acceptable
only if the system fails closed:

- no backend fallback credentials on client machines
- no direct backend MCP config in project repositories
- in front-gateway mode, no direct MCP config for this gateway in project
  repositories
- no write operations when policy, audit, identity-assertion validation, or
  secret storage is unhealthy

Production rollout should add health checks, backup/restore, token revocation
procedures, backend secret rotation procedures, and optional gateway
replication.

**Backup is yours to arrange, and there are three separate things to back up.**
The memory backend holds the only copy of every project's memories, lessons and
actions. The token store decides who can reach anything. The credential store
holds per-user downstream keys, and losing its master key makes every enrolled
credential undecryptable — the gateway degrades loudly rather than silently, but
each user has to enroll again. Paging the memory backend's own REST endpoints is
enough for a full-fidelity dump; note that a local-disk dump protects against
corruption, a bad deploy or an accidentally removed volume, not against losing
the host.

## Docs Corpus Operations

- Config: `DOCS_REPOS_FILE` is hot-reloaded on change (mtime/size/inode), so
  adding or retargeting a project needs no restart. A corrupt or partial write
  keeps the last-good map rather than taking every project's docs tools down.
- The clone keeps full history, because per-file author provenance needs the
  first commit that touched a path. A clone left shallow by an earlier release is
  upgraded in place on the next refresh.
- Reads lag the repository by at most `DOCS_PULL_INTERVAL_SEC` (default 300) —
  but **only for the same repository**. Changing a project's url or branch makes
  the cached corpus ineligible immediately, so a retarget does not wait out the
  interval.
- A fetch failure (or a git timeout) against the same repository serves the last
  good snapshot. A fetch failure on a **newly changed** specification returns 503
  instead: there is no snapshot for it yet, and the one on disk belongs to the
  old repository.
- Documents are read from the git tree, not the checkout: only regular-file
  blobs count, so a committed symlink or submodule is neither followed nor
  listed. A corpus over the caps (5,000 markdown documents, 2 MiB per document,
  64 MiB in total) fails every docs call with a 503 naming the limit until the
  repository is brought back under it; the caps are class attributes on
  `DocsCorpus` for a deployment that must raise them.
- Refresh is per project: one project's slow clone or unreachable remote does not
  block another project's docs calls. Monitor snapshot age per project rather than
  a single global figure.
