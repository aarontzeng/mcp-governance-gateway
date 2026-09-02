# ADR-0012: Vendor-Neutral `issue_project` Tenant Claim

## Status

Accepted

## Date

2026-07-10

## Context

`IssueBackend` is an abstract base with `RedmineHttpBackend` as its only
implementation, so the tool namespace (`issues.*`) is already
capability-shaped. But the **tenant claim was vendor-named**: tokens carried
`redmine_project`, `Policy` hard-checked `principal.redmine_project`, and
`RequestContext` propagated it. Other teams use **GitLab** for
issues, so onboarding them requires a second issue backend — and a project
backed by GitLab has no "Redmine project id". The abstraction was decorative
while the claim that gates it named one vendor.

## Decision

Rename the tenant claim to **`issue_project`** across `Principal`,
`RequestContext`, `Policy`, and the issue backend. Compatibility is
non-negotiable because the claim is **persisted in every issued token**:

- **Dual-read** in the token loader: `issue_project` if present, else the
  legacy `redmine_project`. Tokens minted before the rename keep working with
  **no re-mint and no client reconfiguration** — the bearer string is
  unchanged; only a field name in the server-side token store moved.
- **Deprecated alias**: `Principal.redmine_project` / `RequestContext.redmine_project`
  remain as read-only properties while callers migrate.
- **Dual-write** in the minter: new tokens carry both names, `issue_project`
  authoritative, `redmine_project` retained so an un-upgraded adapter can still
  resolve the tenant (rollback-safe).

## Alternatives Considered

### Leave the claim named `redmine_project`

- Pros: zero work.
- Cons: a GitLab-backed project would have to invent a fake Redmine id, or be
  denied `issues.*` entirely (policy denies a token without the claim).
- Rejected: the rename gets strictly more expensive with every issued token.

### Add a parallel `gitlab_project` claim

- Pros: no rename.
- Cons: policy would branch per vendor; two claims to keep in sync; the tool
  namespace stays capability-shaped while the claims are vendor-shaped.
- Rejected.

### Re-mint every token at cutover

- Pros: one clean field name, no dual-read.
- Cons: a forced revocation for every user, for a rename with no user-visible
  benefit. We spend that budget on genuine identity changes, not cosmetics.
- Rejected.

## Consequences

- A second `IssueBackend` (GitLab) is now a drop-in at the claim layer;
  `server.py` still hardcodes `RedmineHttpBackend` and `config.py` exposes only
  `redmine_*` settings — a per-capability backend binding remains future work.
- Deploying requires an adapter image rebuild (`src/` changed). No token
  re-mint, no client config change.
- The dual-write and the deprecated aliases are removable once every issued
  token carries `issue_project` and no caller reads the alias.

## Enforced By

`tests/test_phase1_mcp.py::IssueProjectRenameCompatTests` (legacy field read,
new field read, new wins over legacy, absent-in-both, integer stringified,
bad type rejected).
