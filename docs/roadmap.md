# Roadmap

What this release deliberately does not include, and what would have to be true
for it to. Items are not dated: this is a reference implementation, and the order
reflects dependency rather than a schedule.

## Docs corpus: images, templates, and other hosts

The write path landed in 0.2.0 for GitHub (ADR-0017): proposals are pull
requests opened under the caller's own credential, and nothing here can merge
one. Three pieces of the original design are still out:

- **GitLab**, and after that anything else. The interface is host-neutral; only
  the GitHub implementation exists. Narrower than it looks: `gitlab_backend.py`
  is already a working GitLab client with per-user PAT resolution through the
  credential store, so the open question is whether the review surface (open an
  MR, add a note, detect a stale write) can reuse its `_request` and its
  credential path rather than what GitLab's API offers. One genuinely external
  unknown remains, and it is empirical rather than documentary: whether a stale
  `last_commit_id` answers 400 or 409. Measure it against a throwaway project
  the way the GitHub statuses were measured; do not take it from documentation
  nobody fetched.
- **Images.** Upstream stages them through a presigned single-use upload so the
  bytes never pass through the agent's context. Inlining base64 in a tool
  argument would undo exactly that, so it waits for the endpoint rather than
  arriving in a worse shape.
- **`docs.review_list`.** The interface has no list operation yet; `review_get`
  answers about a proposal you already know the number of.

Template seeding is not on this list any more: templates are read from
`.mcpgw/templates/` in the corpus itself, which makes the opinion about document
structure the deployment's rather than this project's.

## Corpus linting

A corpus health check — broken links, naming conventions, documents left on an
older template version, correction callouts that were never dated — is
implemented upstream of this release but declines to generalize: every rule
encodes one team's document conventions, and one of them matches Chinese-language
callout markers. It would need to become configurable before it belongs in a
project other people deploy.

## Memory: semantic retrieval

`memory.search` is keyword retrieval. The backend also exposes a hybrid
BM25+vector+graph endpoint (`mem::smart-search`) that is not wired up here,
because it performs no project filtering of its own — and re-verifying every
candidate's tenancy needed a `sessionId -> project` lookup the gateway had no
way to make.

**Re-checked at agentmemory v0.9.29 (`e04ba88`, 2026-08-23), which changes one
of the three blockers:**

- Still true: no `mem::smart-search` entry point uses `project` for memory
  retrieval. It is accepted in the input type and passed only to
  `recallLessons`, which is lesson search.
- Still true: the expand path is capped at 20 ids and filters only by
  `agentId`, never by project.
- **No longer true:** there IS now a REST route carrying a session's project —
  `GET /agentmemory/replay/load` returns `{timeline, session}` and `Session`
  has `project`. But it is a replay loader: the same handler loads every
  observation for the session and builds a timeline, to answer a question that
  is one KV read. So the blocker moved from "impossible" to "possible and
  absurdly expensive", which is a different decision.

The useful shape of the ask is therefore upstream rather than local: the cheap
lookup already exists inside that handler (`kv.get<Session>(KV.sessions, id)`),
and exposing it on its own route — or accepting a project filter in
smart-search — would make semantic retrieval a small change here instead of an
impossible one. Reporting that upstream is the next step, not building a
client-side workaround around a replay endpoint.

Note the related finding now recorded in [SECURITY.md](../SECURITY.md#known-limitations):
the filter `mem::search` does apply fails open for sessions evicted since
indexing, by construction rather than by chance, so today's keyword path is not
the clean baseline the smart-search comparison assumed either. Whatever is done
about semantic retrieval, the tenancy question has to be answered for the
keyword path too — and the retention policy behind it is now
recorded there: nothing evicts on a schedule, so the exposure is zero until an
operator invokes eviction, and the rows that then outlive their session are
preferentially the important ones.

## CI: parameterised triggers

`ci.builds` and `ci.rerun` both shipped in 0.2.0. `ci.rerun` re-runs a job as
configured, behind a trigger allowlist separate from the read one, the
`ci_runner` role and the confirmation gate.

What stays out is a **parameterised** trigger: caller-supplied values reaching a
build are a different trust surface from starting a job whose parameters an
operator already chose, and nothing here validates what a parameter means to a
job. It would need per-job parameter allowlisting to be worth having.

Two limits of what did ship, both inherent rather than bugs: a last-N view
cannot date a failure older than its window, and a job inside a Jenkins folder
cannot be named in either allowlist because names are URL-quoted whole.

## Notifications

Everything here is pull. A red build, a stale review or an overdue action waits
for someone to think to ask. An outbound-only push channel is designed but not
built; reading messages back into agents is an anti-goal.

## Credential enrollment

Settled in 0.2.0. `/internal/credentials` (with `/internal/redmine-key` kept as
a permanent alias) and `/internal/my-issues` are a supported integration
primitive with a written contract in `docs/operations.md`: the ingress boundary,
the fact that the surface acts only on the bearer's own actor, why ADR-0004's
signed identity headers are deliberately not applied there, what an email change
does, and an offboarding order. `ADMIN_PORT` binds them to their own listener,
and the MCP listener then answers 404 for them.

The UI is still not this project's (see "Not planned"), and now needs no
apology: a deployment with an IdP mints nothing at all (ADR-0016), and one
without has `mcpgw-admin`.

## Durable write outcomes and shared state

Two limitations in [SECURITY.md](../SECURITY.md#known-limitations) share one
cause: everything the gateway remembers is process-local. A confirmation, a quota
counter, a docs snapshot and the audit stream all live in one process, which is
why a committed write can be indeterminate after a timeout and why a second
instance is a second enforcement point rather than a replica.

The shape of the fix is known and deliberately not started: a durable operation
identity minted at prepare time, backend idempotency keys where the backend
supports them, and confirmation/quota/credential state in shared storage. Doing it
piecemeal would be worse than not doing it — a durable confirmation with a
process-local quota still multiplies quotas across replicas.

## Not planned

- **A credential-provisioning portal.** Minting tokens, enrolling credentials
  and onboarding projects are deployment concerns with deployment-shaped
  answers (ADR-0007). What this project owes is the *primitive*, and it now
  ships two: OIDC verification (ADR-0016), so a deployment with an IdP mints
  nothing at all, and `mcpgw-admin` for one without. What a self-service page
  looks like — who may open it, how it authenticates, what it shows — is still
  a question with a different answer in every organization, and a UI here would
  be one organization's answer wearing a project's name.
- **`git push` as a tool.** Review comments are not ref updates and may be in
  scope; pushing code is not, until policy and audit controls are proven well
  past their current state.
