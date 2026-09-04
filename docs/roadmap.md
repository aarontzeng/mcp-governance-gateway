# Roadmap

What this release deliberately does not include, and what would have to be true
for it to. Items are not dated: this is a reference implementation, and the order
reflects dependency rather than a schedule.

## Docs corpus: images, templates, and other hosts

The write path landed in 0.2.0 for GitHub (ADR-0017): proposals are pull
requests opened under the caller's own credential, and nothing here can merge
one. Three pieces of the original design are still out:

- **GitLab**, and after that anything else. The interface is host-neutral; only
  the GitHub implementation exists.
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

`memory.search` is keyword retrieval. The memory backend also exposes a
hybrid BM25+vector+graph endpoint, which is not wired up here for two reasons.
It performs no project filtering of its own, so the gateway would have to
re-verify every candidate's tenancy — and the straightforward way to do that
costs a full corpus fetch per query, which does not scale past a small corpus.
And the observations that establish both facts were made against one specific
backend version; publishing them as a general claim about that project, rather
than reporting them upstream, would be the wrong way round.

## CI: controlled rerun

`ci.builds` now answers "is this test flaky" and "when did this start failing"
within the last N builds it returns — a job red for longer than that window
still looks the same as one red since its first build, and a project-wide call
across more jobs than the row budget returns one build each, which answers
neither question and is the point at which to name a job. It reuses the read
allowlist and the read quota; what it adds is volume, not a new class of
disclosure: a series of results and durations rather than a single row.

A rerun tool is a genuine write: it consumes build resources. It would need the
confirmation gate, a dedicated role, and a **trigger allowlist separate from the
read allowlist** — the set of jobs an agent may start is not the set it may
watch. Triggering an arbitrary parameterized build stays out until that is
tighter still.

## Notifications

Everything here is pull. A red build, a stale review or an overdue action waits
for someone to think to ask. An outbound-only push channel is designed but not
built; reading messages back into agents is an anti-goal.

## Credential enrollment: a primitive, not a portal

`docs/security-model.md` and this roadmap say credential provisioning is outside
this project. That is true of the **UI**, and the phrasing has been overclaiming:
the gateway does expose `/internal/redmine-key` and `/internal/my-issues` on the
same listener, which is the API a portal would call. What is missing is the
contract around it — the required ingress boundary (it must not be routed
publicly), the offboarding path, and what happens when a user's email changes,
since enrollment uses email as the proof that a downstream credential belongs to
an actor while ADR-0007 treats email as a display label only.

Either that contract gets written and the routes become a supported integration
primitive, or they should be isolated behind their own listener. Until then, treat
them as unsupported surface: reachable only from the host, and not part of the
compatibility promise.

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
