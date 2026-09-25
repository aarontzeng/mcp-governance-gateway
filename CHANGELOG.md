# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- A `release` workflow: once `ci` is green on `main` and the commit's `__version__` has no release yet, it creates the annotated tag, builds the wheel and sdist, and publishes a GitHub release with that version's CHANGELOG section as the notes (see CONTRIBUTING, "Releasing").

## [0.4.0] — 2026-09-25

### Fixed

- **One tenant could evict another's pending confirmations.** Preparing a write takes no quota and the confirmation store's only bound was its total of 10,000, so a token with a write role could fill it and push every other tenant's pending confirmations out ("unknown or already-used", start over). Each principal now holds at most 64 and, at that bound, evicts its own oldest; filling the total takes 157 principals at once. ADR-0003 and SECURITY.md record the bound.
- **An IdP deployment could not revoke its last runtime token.** With `OIDC_ISSUER` set the runtime token store is legitimately empty, but on reload an empty store counted as a failed parse, so the last-good map — the revoked token — stayed live until another token was minted. An empty store now reloads as empty in that mode; the default deployment (no IdP) still keeps last-good, because there an empty token file is a misconfiguration.
- A `POST /mcp` (or credential enrollment) refused for its `Content-Length` — over 2 MB, or malformed — left that body unread on a keep-alive connection, where it was parsed as the next request. Such a refusal now closes the connection and says so (`Connection: close`).
- `ci.log` dropped the first line of the window even when the window began exactly at a line start; it is dropped only when the byte before the window was not a newline. The window is also trimmed by whole chunks instead of a memmove per chunk.
- The container `HEALTHCHECK` built an unparseable URL for an IPv6 bind (`::` or a literal); `::` is probed on `::1` and IPv6 literals are bracketed.
- A runtime token store that does not exist yet no longer logs "actor labels reload failed" on the first memory or docs read.
- `serverInfo.version` said 0.2.0 on a 0.3.0 gateway. The version is one literal now (`mcp_governance_gateway.__version__`, read by pyproject), and a test holds the newest CHANGELOG heading to it.
- `ci.log` returned the last lines of the console's **first** 512 KB, so on a long log the tail was from the middle. The console is now streamed through a 512 KB window and only its end kept; `logBytes` reports the console's full length; `truncated` is true only when the window held fewer lines than were asked for; a console over 64 MiB is refused (413) rather than mis-tailed.
- SIGTERM (what a container runtime sends on stop) now unwinds `serve_forever` through the same cleanup as Ctrl-C instead of killing the process mid-request.
- A review host answering a write with an empty body (204) was reported as "invalid JSON"; an empty body is an empty object, as every other adapter already read it. A ref reply whose `object` was not an object raised past the error boundary.
- A docs refresh whose fetch brought no new commit re-read every blob, replayed the whole log and rebuilt the index; it now only moves the freshness stamp.

### Added

- `DOCS_GIT_TIMEOUT_SEC` (default 30): the per-call git timeout the docs corpus always had and nothing configured.
- `/healthz` reports `version`. It is unauthenticated, so an ingress that publishes it publishes the version (see operations.md).
- The container image has a `HEALTHCHECK` against `/healthz`, and its base is pinned by digest; Dependabot's docker ecosystem moves the pin monthly.
- operations.md tabulates the process-local state, its bound and what reclaims it — including that tracker project ids are cached until restart and that a retargeted docs project leaves its old clone on disk.

### Changed

- Bearer lookup is by the token's SHA-256 rather than a comparison with every stored token: measured 108 µs → 5.3 µs per request at 1,000 tokens, 537 µs → 13 µs at 5,000.
- **Credential enrollment names its backend.** Audit events are `credentials.set` / `credentials.clear` (were `redmine.key.set` / `redmine.key.clear` on every deployment, GitLab included); refusals name the deployment's tracker; the enrollment response and `status` carry `login` beside `redmineLogin`, which deployed enrollment pages still read. The store class is `CredentialStore` (`RedmineKeyStore` remains an alias); the `REDMINE_KEYSTORE_*` variables are unchanged.
- **Diagnostics go through `logging` to stderr**, each line with a level and the module that spoke. The "listening on" lines no longer go to stdout, which is now the audit stream's alone.
- **Unrouted paths answer 404 for every method** (an unrouted GET or DELETE used to answer 405); a served path asked for with a method it does not take answers 405, as `GET /mcp` always has.
- A CI JSON or text reply over 512 KB is refused ("CI response too large") instead of being cut mid-body and reported as invalid JSON.
- A corrupt actor-labels file is logged, like every other hot-reloaded file, instead of being kept silently.

### Internal

- Every adapter error subclasses `errors.BackendError`; `CiBackendError` and `ReviewBackendError` are real classes rather than aliases of the tracker's.
- `hotfile.ReloadingFile` replaces five change-detected reload loops with one (last-good, logged and throttled, `stale`, reloads serialized); the credential store's read path is now under that lock. `hotfile.atomic_write_json` is the one atomic writer for the token store and the credential store.
- `http_client.JsonHttpClient` replaces five copies of the urlopen / error-mapping / body-cap / decode path.
- `mcp.py` is split: `tools/` holds one `ToolSpec` per tool beside its family's handler, `policy.py` derives its decision from the spec, and `tools/list` filters the same records; a test walks every roles × tenant × features combination and holds discovery to policy.
- `GatewayApp` takes any `confirm.ConfirmationBackend`; `tests/test_confirm_contract.py` states what a shared implementation must keep. `ConfirmationStore` stays the default.
- The attribution footer lives in `attribution.py`; a test pins the exact bytes issue notes and review comments carry.
- `ReloadingFile(load_now=True)` takes the file's signature before the boot-time parse, so an atomic replace landing during the parse is reloaded next time rather than recorded as seen.
- `GitHubReviewBackend` keeps one HTTP client per review host instead of building one per call; `configure_logging` is idempotent; attributes the shared HTTP client made unused are gone.
- `server.py` routes from one table, builds each backend in its own factory, and streams artifacts from `artifact_route.py`.
- `tests/test_phase1_mcp.py` (3100 lines) is seven files named for what they cover; ruff (correctness rules) and mypy over all of `src` run in CI.

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
