# ADR-0013: Issue Backend Selected per Deployment, Not per Project

## Status

Accepted

## Date

2026-07-10

## Context

ADR-0012 made the tenant claim vendor-neutral and `GitLabHttpBackend` now
exists alongside Redmine. The remaining question is binding: does one gateway
deployment route *each project* to its own tracker, or does a deployment run
*one* issue backend for all its projects? All three current tenants use
Redmine; the GitLab-using projects are separate teams that would onboard as
their own deployment or later.

## Decision

**One issue backend per deployment**, selected by `ISSUE_BACKEND`
(`redmine` default | `gitlab`) with its own settings (`GITLAB_BASE_URL`,
`GITLAB_TOKEN`). Guards fail loud at boot: an unknown backend name refuses to
start, and `REDMINE_ENFORCE_PERSONAL_KEY` with the GitLab backend is rejected
rather than silently ignored (the per-user keystore is Redmine-specific until
the credential store is generalized). The portal-facing internal API
(redmine-key page, my-issues) wires only when the backend is Redmine, so a
GitLab deployment 404s cleanly there.

GitLab v1 boundaries: shared token + attribution footer (per-user PATs wait
for the multi-backend credential store); statuses map to GitLab's two states
(OPEN/CLOSED — workflow beyond that lives in labels, and `done_ratio` is
rejected, not dropped); issues are addressed by the project-scoped `iid`.

## Alternatives Considered

### Per-project capability→backend routing now

- Pros: one deployment could serve Redmine and GitLab tenants at once.
- Cons: a routing table, per-project credentials, split confirmation/audit
  semantics — built before any deployment actually mixes trackers.
- Deferred, not rejected: the claim layer (ADR-0012) already supports it; add
  routing when a real mixed deployment exists.

### Auto-detect from which base-URL env is set

- Pros: one less variable.
- Cons: setting both silently picks one; explicit beats implicit for a
  security boundary.
- Rejected.

## Consequences

- A GitLab team onboards by running a gateway deployment with three env vars —
  no code changes.
- Mixed-tracker deployments remain unsupported until routing is added.
- `issues.update_status` semantics differ by backend (Redmine workflow names
  vs GitLab OPEN/CLOSED); the tool description stays generic and the backend
  error names the allowed values.

## Enforced By

`tests/test_gitlab_backend.py` (tenancy re-filter, iid addressing, attribution
footer, status mapping, done-ratio rejection) and the boot guards in
`server.py::build_server`.
