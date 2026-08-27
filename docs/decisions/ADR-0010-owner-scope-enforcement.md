# ADR-0010: Owner-Scope Enforcement Trust Boundary

## Status

Accepted — with field experience worth reading before you adopt it, recorded
below under "Field Experience".

## Date

2026-07-10

## Context

Multiple people develop with AI agents in the same repos. An agent told to fix
module A will happily "improve" module B on the way past; a prose rule in
`AGENTS.md` is advice, not a check. We need machine-readable ownership and an
enforcement point — knowing that **the check itself will be attacked by the
agents it polices** (an agent told to "make the check pass" will try anything
textual), and that on our Gerrit 2.15 core ACLs are per-ref, not per-path.

## Decision

Ownership lives in `OWNERS` files in the **find-owners (Chromium) format**, so
the same files can later drive Gerrit's `find-owners` submit rule unchanged.
`scripts/check_owners.py` evaluates a change with this trust boundary:

- **Governance is read from the BASE tree** (merge-base of target and rev),
  never from the change: a change cannot grant itself ownership, delete the
  OWNERS that governs it, or exempt itself via `.owners-exempt`.
- **Review mode requires the authenticated uploader** passed in explicitly;
  the commit's own author field is forgeable and is used only in local
  advisory mode.
- The changed set is the diff against the base, so a merge commit cannot wrap
  and skip a crossing; paths are parsed NUL-delimited with `core.quotePath`
  off so non-ASCII names cannot dodge the lookup; unparseable input fails
  closed.
- `Cross-Owner: <reason>` is a **reason, not permission**: review mode also
  requires an owner of **every** crossed path among the approvals.

Deployment is layered: **context** (a project's agent-guideline docs), **belt**
(the `commit-msg` hook in `scripts/check_owners.py`; if the repo uses
`core.hooksPath` — e.g. for Gerrit's Change-Id hook — chain to it, since it
shadows `.git/hooks`), **braces** (a server-side gate: a Gerrit submit rule or
a CI job that reruns the check as a required status). The hook never
writes `OWNERS` itself: ownership maps land via review.

## Alternatives Considered

### GitLab-style CODEOWNERS in Gerrit

- Pros: platform-native, zero custom code.
- Cons: Gerrit has no CODEOWNERS; core ACLs are per-ref; the `code-owners`
  plugin needs Gerrit 3.x (we run 2.15).
- Rejected on Gerrit (GitLab projects use real `CODEOWNERS`); `find-owners` /
  Prolog submit rules remain the native option to adopt.

### Trust the commit author (%ae) in CI

- Pros: no wiring to fetch the uploader.
- Cons: `git commit --author=` defeats the whole check in one flag.
- Rejected after an adversarial review reproduced the bypass.

### Read OWNERS from the change's own tree

- Pros: simplest implementation.
- Cons: the change can grant its author ownership in the same commit — the
  escape-hatch lock reopened one layer down.
- Rejected after the same review reproduced it.

## Consequences

- The local hook is a **belt**: `--no-verify` bypasses it by design; real
  teeth come from the server-side **braces** (submit rule / required CI status),
  which the client cannot skip.
- `per-file` binds to the OWNERS file's own directory (find-owners semantics);
  drifting from that would silently change ownership on migration to the
  native rule.
- Unowned paths are allowed — adding one OWNERS file must not lock a repo.

## Enforced By

`tests/test_check_owners.py` (43 tests, including git-layer integration tests
that replay each reviewed bypass: same-commit OWNERS/exempt self-grant, forged
author, non-ASCII path, merge wrap).

## Field Experience

The deployment this came from **withdrew the belt** roughly three months in. The
checker itself worked; the surrounding conditions did not, and all three failures
are ones a new adopter can walk into:

- **The braces never landed.** Only the local `commit-msg` hook was ever
  installed, and `--no-verify` bypasses it by design. Without the server-side
  gate this ADR calls for, the whole mechanism was advisory — so it produced
  friction without producing the guarantee.
- **Nobody wrote a real ownership map.** Every repository ended up with a single
  blanket root `OWNERS`, which is the degenerate case: it names one owner for
  everything rather than binding modules to the people who know them.
- **A blanket root owner blocks everyone.** With one owner on `*`, every
  colleague crossed ownership on every path, so `Cross-Owner:` stopped being a
  signal and became a line people typed to get their commit through.

None of that argues against the design; it argues against deploying the belt
first. If you adopt this, define a real per-module map and land the server-side
gate **before** the hook reaches anyone's machine. A belt with no braces trains
people to route around it, and that habit outlives the tooling.

`scripts/check_owners.py` is standalone and does not require the gateway, so it
remains available on those terms.
