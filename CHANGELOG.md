# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.3.0] — 2026-09-11

### Docs corpus

- `docs.review_list` lists open corpus proposals, newest updated first, with author ownership and a bounded result count.
- `docs.review_add_reviewer` requests a named account's review idempotently, behind `docs_reviewer` and a confirmation bound to change and reviewer.
- `docs.review_abandon` lets a `docs_writer` withdraw their own open proposal after confirmation, with an optional stamped comment; no branch deletion, no merge, no approve.
- `docs.lint` reports missing titles, broken relative Markdown links and duplicate slugs from the served snapshot, including on read-only corpora; findings, never a verdict.
- `docs.asset_stage_url` plus a bearer-authenticated PUT route stage up to 2 MiB of UTF-8 Markdown for `contentStaged` create/update proposals: one-shot 60 s upload URL, 3600 s stage, per-user quotas, ownership bound to actor, project and token, consumed on a successful proposal and reusable after a failed one.
- Staged uploads resolve signed forwarded identity exactly as `/mcp` does.
- Two projects can no longer map the same docs repo URL (case-insensitive); ADR-0017 amended for the seven-operation review interface.

### Issues

- `issues.create` and `issues.update_status` accept `startDate`, `dueDate` (YYYY-MM-DD, field-aware errors) and `priority` (name → id); on GitLab all planning fields are refused loudly rather than dropped.
- `issues.get` / `issues.mine` rows carry `priority` (lower-cased name or null) and `dueDate` (or null); GitLab rows: priority null, due date passed through.

### CI

- `ci.stop` cancels a queued item or stops a build, behind the same `ci_runner` role, trigger allowlist and confirmation as `ci.rerun`; queue ownership is checked before any cancellation.

### Memory

- `memory.lesson_list` and `memory.action_list` fetch a bounded project window (5 000) from the backend before filtering and paging, so the backend's default page can no longer hide a project's rows; results report `total` and `truncated`.

### Operations

- `scripts/mcpgw-token-backup.sh`: a daily, lock-guarded, shrink-refusing archive of the user-token store.
- `scripts/check-tokens-intact.sh`: snapshot before a deploy, verify after — no issued token may disappear, change, or stop authenticating.

## [0.2.0] — 2026-09-04

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
- **`mcpgw-admin`** — a reference minter for deployments without an identity
  provider, satisfying what ADR-0007 asks of one: tokens from `secrets`, and an
  atomic `mkstemp` + `fchmod 0600` + `fsync` + `os.replace` write. Subcommands
  `mint`, `rotate`, `revoke`, `list`, `grant`, `revoke-role`. It writes whatever
  `--store` names, defaulting to `GATEWAY_USER_TOKEN_FILE`, and refuses when that
  resolves to the same file as `GATEWAY_TOKEN_FILE` — a guard against the obvious
  slip rather than a boundary, since it can only compare what is in the *admin*
  shell's environment; `--actor` is never defaulted; the token is printed once
  and `list` shows `token_id` instead. It is not a portal — what a self-service
  credential page looks like remains a deployment's own question.

- `ci.builds` — recent build history, newest first (1–50 rows per job, default
  10). `ci.status` reports the last build only, which cannot distinguish a job
  failing since a known build from one that fails intermittently. `job` is
  optional: omitted, it answers for every job in the project in a single call,
  sharing one row budget. Rows carry `startedAt` (ISO-8601) beside the raw
  Jenkins `timestamp`. Read-only, same allowlist and read quota as the rest of
  the `ci.*` family. Across many jobs the per-job count is reduced silently to
  keep one shared row budget (200); with more allowlisted jobs than that, every
  job returns one build and the answer is as wide as `ci.status` already is.

- `ci.rerun` — start a build of one job. The only `ci.*` tool that changes
  anything, and it is gated three ways: a **second** allowlist
  (`CI_TRIGGER_JOBS_FILE`, the jobs a project may *start*, which is not the list
  `ci.status` shows), the new `ci_runner` role, and the confirmation gate. It
  takes no build parameters — it re-runs the job as configured. It returns the
  **queue item**, not a build number, because the build does not exist until
  Jenkins's quiet period elapses; two reruns inside that window are coalesced
  into one build, which `alreadyQueued` reports rather than pretending
  otherwise — three-valued, because `true` is the only certain answer and
  rounding "could not tell" down to `false` is what makes an agent wait for a
  build that never arrives. `JENKINS_TOKEN` must be an API token: Jenkins exempts those from
  CSRF and refuses a password POST without a session-bound crumb, and a 403 now
  says so instead of reading as a permissions problem.

- **The docs corpus write path (ADR-0017)** — `docs.create`, `docs.update`,
  `docs.review_comment` and `docs.review_get`. A write does not publish: it
  opens or revises a **pull request** on the project's review host, under the
  **caller's own credential**, and there is no tool that merges one — the
  review-backend interface has no merge, approve or push method, so no
  configuration mistake can produce one. That makes the *gateway* unable to
  publish; the property as a whole also needs a narrowly-scoped enrolled token
  and a repository that does not let an author merge their own pull request
  unreviewed, both of which are the deployment's (ADR-0017 says which, and the
  enrolment refusal now names the exact token scope). A comment is a plain comment: verified
  against GitHub that it creates no review and cannot satisfy a
  required-approvals rule.

  Per project, and off by default: a corpus stays read-only unless its entry in
  `DOCS_REPOS_FILE` carries a `review` block. Two roles, because proposing a
  document and giving an opinion on someone else's are different acts:
  `docs_writer` and `docs_reviewer`. All three writes are confirmation-gated and
  secret-scanned. `docs.create` refuses a path that exists; `docs.update` carries
  the `sha` that `docs.get` now returns, so a document that moved under the agent
  is a 409 rather than a silent overwrite. A proposal may only name a document
  the read path would serve — under a served directory, ending in `.md` — so the
  tools cannot propose a workflow file or a source file.

  GitHub only in this release. The interface is host-neutral and GitLab is next.

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
