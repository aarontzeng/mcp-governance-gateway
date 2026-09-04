# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **OIDC access-token verification (ADR-0016)** — an optional second
  authenticator beside the token file, so a deployment with an identity
  provider mints nothing by hand. The token file is consulted first, and a
  deployment that sets no `OIDC_*` variables behaves exactly as before;
  `GATEWAY_TOKEN_FILE` becomes optional only when `OIDC_ISSUER` is set. The
  IdP supplies the identity (`sub` → actor, `email` as a label); tenancy comes
  from `OIDC_GRANTS_FILE`, resolved by subject then by group, so a `project`
  claim inside a token is ignored. Signature algorithms are an allow-list in
  code — `alg: none` and every HMAC algorithm are refused before a key lookup —
  and `OIDC_AUDIENCE` is required with no default. The key set is cached, with
  last-good kept across an IdP outage. No new dependency: `cryptography` was
  already required.

- `ci.builds` — recent build history, newest first (1–50 rows per job, default
  10). `ci.status` reports the last build only, which cannot distinguish a job
  failing since a known build from one that fails intermittently. `job` is
  optional: omitted, it answers for every job in the project in a single call,
  sharing one row budget. Rows carry `startedAt` (ISO-8601) beside the raw
  Jenkins `timestamp`. Read-only, same allowlist and read quota as the rest of
  the `ci.*` family. Across many jobs the per-job count is reduced silently to
  keep one shared row budget (200); with more allowlisted jobs than that, every
  job returns one build and the answer is as wide as `ci.status` already is.

### Changed

- `ci.status` rows now carry `startedAt` (ISO-8601) beside the existing
  `timestamp`, because both tools share one row normalizer — which is what stops
  them drifting again. Two behaviours of `ci.status` changed with it: a
  non-string `result` from Jenkins now reads as `UNKNOWN` instead of being
  passed through, and a last-build reply with no usable build number now returns
  the never-built row (all fields null) instead of a partial one. The never-built
  row also carries the same keys as a real one, so a caller no longer has to
  branch on which fields are present. `timestamp` and `durationMs` are no longer
  passed through untouched either: a non-numeric value from Jenkins becomes
  `null` and a fractional millisecond is truncated to an integer.
- `ci.log` returns its `build` and `result` from the same last-build row as
  `ci.status`, so the three changes above reach it as well: a non-string
  `result` reads as `UNKNOWN`, and a last build with no usable build number
  reads as `build: null, result: "UNKNOWN"` rather than echoing whatever
  Jenkins sent. The console tail itself is unchanged.

## [0.1.0] — 2026-09-02

First public release.

- MCP server (`tools/list`, `tools/call`) over HTTP with bearer-token
  authentication, per-token project binding and role-based policy.
- Backends: agentmemory (memories, lessons, actions), Redmine and GitLab issues,
  a per-project read-only docs corpus backed by git, Jenkins CI status/log and
  an artifact download data plane.
- Confirmation-gated issue writes bound to their exact arguments; per-user
  downstream credentials encrypted at rest; secret scanning on memory writes;
  per-user and per-project write quotas.
- JSON-lines audit stream naming the acting identity on every call.
