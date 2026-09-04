# ADR-0017: An Agent May Propose a Document, and Only a Person May Publish It

## Status

Accepted

## Date

2026-09-04

## Context

The docs corpus was read-only. The write half was described in the roadmap as
"the most interesting governance property in the whole system — an agent can
propose and advise, but only a person can publish", and then not implemented,
because the upstream version of it was built around one organisation's Gerrit
and a per-user SSH key store.

The question is not whether an agent should be able to change documentation. It
is **what stops the change from taking effect on its own**. Three answers were
available:

1. A policy check: let the code merge, and refuse when a flag says not to.
2. A capability the deployment grants: a token whose scope excludes merging.
3. No method: the interface a review host implements has nowhere to put it.

## Decision

**A proposal is a pull request, opened under the caller's own credential, and
the interface has no way to merge one.**

`review_backend.ReviewBackend` has exactly four operations — open a change,
revise it, comment on it, read it back. There is no `merge`, no `approve`, no
`delete_branch`, no `push`. Answer (3): adding one is a code change to a file
whose docstring says why it must not happen, not a misconfiguration.

**And answer (3) alone is not the property.** It makes the GATEWAY unable to
publish, which is the part this project can own. The property as a whole needs
two more things that belong to the deployment, and stating only the first would
be overclaiming:

- **The credential must not be able to publish.** The enrolled token is the
  caller's own. If it carries more than "open a pull request", the power to
  merge exists even though this code never uses it. The narrowest token that
  works is Contents: read/write and Pull requests: read/write on that ONE
  repository; the 428 a caller gets before enrolling now says exactly that,
  because otherwise people enrol whatever the host's UI calls "read and write".
- **The repository must not let the author merge unreviewed.** Otherwise the
  person who publishes is the same identity that proposed, and the separation is
  a second browser tab rather than a second principal.

An agent talking only to this gateway cannot publish under any settings: the
credential never leaves the process, so the agent holds the gateway's tools and
not the token. What the other two protect against is the human's own token being
used elsewhere, and a repository where proposing and publishing are one act.

Answer (1) was rejected because a policy check is a thing that can be wrong: a
default, an inverted condition, a deployment that sets a flag it does not
understand. Answer (2) is real and complementary — a deployment should give the
token the narrowest scope that works — but it is the deployment's to get right,
and this project should not depend on it.

**Under the caller's own credential, or not at all.** There is no shared service
account for the write path and no fallback to one. A caller who has not enrolled
gets a 428 that says how to. This is what makes "an agent may propose" a claim
about an accountable human: the pull request carries a person's name, the review
host's own access control is the authorization, and someone who should not be
able to change that repository still cannot.

**Comment, never approve.** `docs.review_comment` posts an issue comment.
Verified against GitHub that this creates no review and leaves `reviewDecision`
null, so an agent's opinion provably cannot satisfy a required-approvals rule.
The endpoint that could — `POST /pulls/{n}/reviews` — is not called anywhere,
and that is the point rather than an omission. Every comment carries the gateway
footer, because an unstamped comment is indistinguishable from one the person
wrote themselves.

**A proposal may only name a document the read path would serve.** Under a
served directory, ending in `.md`, no dot-prefixed segment. Without this the
tools are a general "propose any file into this repository" primitive, and a
workflow file is a much better lure than a Markdown file when it arrives through
something called `docs.create`.

**Per project, off by default.** A corpus is read-only unless its entry names a
`review` host. A malformed block is a boot error, because an operator who wrote
one believes writes are on.

**Two roles.** `docs_writer` proposes; `docs_reviewer` comments. They are
different acts and a deployment may want to grant only the second.

## Alternatives Considered

### Push a branch from the corpus clone

- Pros: no host API to implement; works for any git host.
- Cons: the clone is the read path's cache, so a write would race the refresher;
  and the caller's credential would have to reach a `git` command line, where a
  process listing can see it.
- Rejected. The REST route keeps the clone read-only and the credential in a
  header.

### Port the existing Gerrit implementation

- Pros: it exists and is in production somewhere.
- Cons: `refs/for/*`, the `commit-msg` hook fetched over scp, Change-Id
  semantics and a ±1 vote model have no equivalent in a pull-request flow, and
  almost no adopter of this project runs Gerrit.
- Rejected as the first implementation; the interface is host-neutral and Gerrit
  remains implementable behind it.

### Allow an advisory vote (±1) rather than a comment

- Pros: closer to the upstream design; carries more signal.
- Cons: GitHub has no advisory vote. The nearest equivalents — an APPROVE or
  REQUEST_CHANGES review — both count toward a branch protection rule, so the
  "advisory" framing would be false on the host where it matters.
- Rejected. A comment is the strongest thing that is honestly advisory.

## Consequences

- Publishing is a human action on the review host, with that host's own audit
  trail, review UI and protection rules. This project does not reimplement any
  of it.
- A deployment must enrol per-user credentials for the docs host. That is real
  operational cost, and it is the cost of attribution.
- The tools are useless on a repository whose settings let the proposer merge
  their own pull request unreviewed. **This ADR constrains what the gateway can
  do; it cannot constrain what the host allows.** `docs/adapters/docs.md` says
  so, and says which repository settings actually carry the property.
- Abandoned proposal branches accumulate. Nothing here deletes them, because
  deleting a branch is a write this interface deliberately cannot do.
