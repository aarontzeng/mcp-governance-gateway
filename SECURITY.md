# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately rather than via a public
issue. [Open a security advisory](https://github.com/aarontzeng/mcp-governance-gateway/security/advisories/new) — that form is
private to the maintainers until an advisory is published. If you cannot use it,
open a normal issue saying only that you have a security report and asking for a
contact channel; do not put the details in it.
We aim to acknowledge within a few working days.

Please include what you were able to do, the token/role you held, and whether
the issue crosses a tenant boundary — those are the reports we treat as most
severe.

## What the gateway defends

The gateway's threat model assumes the agent (and therefore the MCP client) may
be adversarial or compromised, and that a token may be stolen. Its guarantees:

- **Tenant isolation is server-side.** The project/tenant is resolved from the
  token, never taken as a tool argument. A stolen token confines the attacker to
  that one project; it cannot be widened from the client.
- **Issue writes are least-privilege and confirmation-gated.** They need an
  explicit role; the confirmation id is single-use, short-lived, and bound to the
  exact arguments, so it cannot be replayed to repeat or alter a write. Memory
  writes are gated by tenancy and quota only — see
  [the authorization table](docs/security-model.md#authorization-as-implemented)
  for exactly which tools check what.
- **Credentials are encrypted at rest.** Optional per-user backend credentials
  use AES-256-GCM with the ciphertext bound (via AEAD associated data) to the
  owner and the backend, so a record cannot be re-purposed as another user's or
  another backend's credential; tampering the stored backend label fails closed.
- **No secrets in transcripts or logs.** Tokens and credentials are never echoed
  back, and the audit log records fixed names rather than caller-supplied
  strings for refused tool names and artifact ids. Backend errors are
  normalized so they cannot leak another tenant's data or confirm the existence
  of a resource in another project — with one documented exception under
  "Known limitations".

## What it does not defend

- The confidentiality of data a correctly-scoped token is *authorized* to read.
- Backends' own security (agentmemory, Redmine, GitLab, Jenkins) — the gateway
  constrains access to them; it does not harden them.
- Transport security — terminate TLS at a reverse proxy in front of the gateway.

## Known limitations

Deliberate boundaries of this release, stated so a deployment does not discover
them the hard way. Each one is a property an adopter might reasonably assume and
should not.

**A committed write is not a transactional one.** The confirmation is consumed
before the backend call, and the audit event is written after it returns. A
timeout after the backend has committed therefore leaves an indeterminate write:
retrying goes through a fresh prepare/commit and can duplicate an issue or a note.
There is no durable operation record and no backend idempotency key. Audit is a
JSON-lines stream, so an audit failure after a committed write loses the record of
it. Treat the audit log as a record of what the gateway decided, not as proof of
what every backend did.

**Memory search trusts the backend's project filter.** `memory.search` sends the
token's project to agentmemory and returns what comes back; the hits carry no
project field, so the gateway cannot re-filter them the way it re-filters issue
and docs results. A backend that ignores its own filter would leak across tenants
through this one tool — and this is sharper than a hypothetical. Read at
agentmemory v0.9.29 (`e04ba88`), `src/functions/search.ts:541-566`:
`mem::search` does filter per row, by loading each hit's session and comparing
`session.project`. When the session is *not* found it takes a **deliberate
fail-open branch**, and its own comment enumerates two cases:

- a memory indexed with a synthetic sessionId is still filtered, because a
  probe into the memories store returns that memory's own project;
- **an evicted session is not.** The comment says the probe "returns null for
  these (they are observations, not memories)", so for this case the fallback
  yields null *by construction* rather than by chance, and the row passes
  through unscoped. The code calls that "the safe fallback" — safe for
  availability, fail-open for tenancy.

So a hit whose session has been evicted since indexing reaches the caller
whatever project was asked for, and the gateway cannot detect it because the
hits carry no project field for it to re-check.

The operational shape, read from `src/functions/evict.ts` at the same commit,
is the part to plan around — and it is not a clock:

- **Nothing evicts on a schedule.** `mem::evict` has no cron and no timer; its
  only caller is an HTTP route. A deployment that never invokes it never
  orphans a row, and this limitation never fires.
- Once invoked, it deletes a **session** whose `startedAt` is older than
  `staleSessionDays` (default 30) and which has no summary. Note `startedAt`,
  not last activity: a long-running session is stale by age, not by idleness.
- It deletes an **observation** under different criteria entirely — importance
  below `lowImportanceThreshold` (default 3) *and* older than
  `lowImportanceMaxDays` (default 90).

Those two policies disagree, and the gap is the exposure: a row survives its
session when it is younger than 90 days **or** important enough to keep. So the
orphaned, unscoped rows are preferentially the ones marked as mattering most.
That follows from the two thresholds rather than from anything observed at
runtime, and it is the reason to treat this as a boundary to check rather than
a corner case.

If you need a number for a specific deployment, the eviction route accepts a
dry run and reports the stale-session count without deleting anything.

Treat `memory.search` results as scoped by a filter that is best-effort at the
backend, not as a tenant boundary this gateway enforces. `memory.action_update_status` checks the target's project
by listing first and then updates by id, so a record re-homed between the two
calls is updated on its new project.

**Issue writes are check-then-write too.** `issues.add_note` and
`issues.update_status` verify the issue's project with a read and then write;
neither Redmine nor GitLab offers a conditional write. What an issue moved to
another project between the two calls receives depends on the backend: Redmine
writes by global id, so the write lands on the issue in its new project; GitLab
writes through the checked project's own path, so the write never follows the
issue into a project the check did not see. The window is one round-trip and
the write still lands under the caller's own credential when one is enrolled.

**One 403 names a project the shared key can see.** When a caller's personal
Redmine key is refused with 403 for an issue their own account cannot read, the
gateway says so ("no access in this project") instead of the uniform "issue
not found", because that message names the fixable cause. For an issue in
another project that the shared key can read but the caller's cannot, this
makes cross-project existence distinguishable — a subset of what the tracker
already discloses to that same account directly. GitLab has no such message:
a personal PAT that cannot read the issue gets the tracker's own 404 as "issue
not found", or its 403 passed through as `issue tracker HTTP 403`.

**Secret scanning is best-effort.** Memory writes are rejected when they contain
a credential-shaped unbroken blob (a PEM key, a well-known token prefix, a JWT, a
`key=value` assignment). Values broken up with hyphens or spaces, or in formats the
patterns do not know, pass by design; the scanner is a guardrail against the
accidental paste, not a data-loss-prevention boundary.

**A confirmation is bound to the identity, not to the credential, for OIDC
callers.** `confirm.py` binds a pending write to `actor | project | token_id |
issue_project | tool`. For an opaque token `token_id` is a hash of the token
string, so a confirmation can only be committed by the credential that prepared
it. For an OIDC caller it is derived from `iss|sub` — deliberately, so a token
refresh does not expire a pending confirmation mid-flow (ADR-0016) — and it
therefore adds nothing beyond `actor`. A second session of the same person can
commit a confirmation the first prepared, given identical arguments. That session
already had the authority to prepare the same write itself, so this is not an
escalation; what it means is that a leaked `confirmationId` is a *user*-level
capability for its 300-second life rather than a credential-level one. Treat a
confirmation id as you would the write it authorizes.

**One active instance.** Everything the gateway remembers between calls lives in
the process. The full list, because "quotas" was doing too much work in an
earlier version of this sentence:

- confirmation nonces (`confirm.py`);
- the memory read and write quotas (`limits.py`);
- **the credential-enrollment API's own two rate limiters** — writes and reads
  are separate counters (`internal_api.py`), and they are not the memory quotas;
- docs corpus snapshots and their registry generation (`docs_backend.py`);
- the OIDC key cache and grants mapping (`oidc.py`);
- the audit stream (`audit.py`), and the credential store, which is guarded by
  a lock on the instance rather than on the file.

Two instances behind a load balancer are two enforcement points, not one: a
prepare on A cannot commit on B, every one of those counters multiplies by the
instance count, and concurrent credential enrollment can lose a record — or,
worse, undo a revocation, which the paragraph below describes. Run one active
instance until that state moves to shared storage.

**`DOCS_CLONE_DIR` belongs to one instance, and this one is not a degraded
guarantee.** Two gateways sharing that directory both `fetch` and
`reset --hard` the same working tree. Until 0.2.1 the clone was keyed by
project NAME alone, so two instances whose repos files mapped one project name
to different repositories shared a directory and each served the other's
documents under its own configured corpus — content across a tenant boundary,
and undetectable downstream because the snapshot's recorded commit and its
documents came from different commits. The key now includes the repository url,
which makes that collision impossible; two instances with the SAME url still
race over one working tree, so give each instance its own directory.

Worth stating more sharply than "can lose a record", because one case is
fail-OPEN rather than fail-safe: the credential store's read-modify-write is
serialized by a `threading.Lock` on the instance, not by a lock on the FILE. Two
processes sharing one store can therefore interleave so that an enrolment
already in flight rewrites a record a `DELETE /internal/credentials` just
removed — the delete returns `{"cleared": true}` and audits `ok`, and the
credential is live again a moment later. A revocation that reports success and
does not stick is the reason the offboarding order in `docs/operations.md`
assumes the single active instance this section requires. (Demonstrated in
review, 2026-09-04.)

**"Last good" applies to authorization state too.** A token file that becomes
unreadable leaves the previously loaded claims live, so an emergency revoke that
corrupts or truncates the file may not take effect. Verify a revoke by observing a
rejection, not by observing that the file changed. In optional per-user credential
mode, an unavailable keystore fails closed for reads whose meaning is the caller's
identity (`issues.mine` on both trackers; on Redmine also any read by an enrolled
caller, which is routed on their own key) and for writes when the backend's
enforce-personal-key switch is set; otherwise writes fall back to the shared
backend credential, so native authorship becomes the service account's while the
attribution footer still names the real actor.

**Identity propagation is an attribution override, not an authentication hop.**
The signed-header path verifies an HMAC over `user_id:email` and nothing else — no
issuer, audience, expiry or replay id — and a request without those headers
silently uses the token's own actor. Do not treat a propagated identity as
independently authenticated, and do not rely on the absence of headers being
noticed.

**Encryption at rest is not key management.** The keystore's master key is read at
startup, so rotating it requires a restart — the multiple-key support removes the
need to re-enroll credentials, not the need to roll the process. If the ciphertext
and the master key share a host or a backup, encryption is protecting against a
narrower set of disclosures than it appears to.

**Provenance is commit metadata.** `createdBy`/`updatedBy` come from Git's author
name, which is supplied by whoever made the commit. Branch protection and review
on the repository are what make that trustworthy; the gateway does not verify it
and it is not an identity assertion. Do not let an authorization decision depend
on it.

**Health is liveness, not readiness.** `/healthz` reports that the process is up
and whether the keystore is degraded. It does not check backends, audit, or
configuration, so it must not be used to decide whether an instance is safe to
route writes to.

**The docs corpus is sized for reviewed prose.** A refresh reads documents from
the git tree (never through the checkout, so a committed symlink is not followed)
and refuses the corpus outright — every docs call is a 503 naming the limit until
the repository is brought back under it — when it exceeds 5,000 markdown
documents, 2 MiB for one document, or 64 MiB in total. Below those
caps nothing else is bounded: the clone keeps full history and the listing is
whole-corpus. Monitor snapshot age, refresh duration and clone disk; a corpus that
outgrows "small" shows up as refresh latency and memory before request rate does.

**Read access to externally governed repositories.** The gateway serves the docs
corpus; it does not create, review, validate or maintain it. Declared lifecycle
fields (`status`, `stale_after`, `decision_status`) are passed through untouched —
they are the repository's claims, not gateway-enforced guarantees.

**One issue tracker per deployment** (ADR-0013). This is coherent while a
deployment is dedicated to one tracker. A genuinely mixed deployment would have to
route per project through tokens, credential storage, confirmation recovery and
audit identity at once; it is not a drop-in second adapter.

## Hardening checklist

- Serve behind TLS; restrict the listener to trusted networks.
- Give each backend credential the narrowest scope that works (a project-scoped
  issue account; a CI token that can read the jobs on `CI_JOBS_FILE`, and can
  trigger builds only if you configure `CI_TRIGGER_JOBS_FILE` — without that
  file the gateway never POSTs to Jenkins, so a read-only CI token is right).
- Rotate the keystore master key and backend service credentials periodically.
  Multiple master keys mean a rotation does not force users to re-enroll; it does
  still require a restart to load the new key.
- Run exactly one active instance, and monitor snapshot age, artifact-download
  outcomes and keystore degradation — see "Known limitations".
- Keep the audit log on separate, append-only storage.
