# ADR-0009: Per-User Downstream Credentials, Encrypted at Rest, Enforced for Writes

## Status

Accepted. Generalized to any issue backend by ADR-0012/ADR-0013: the store gained
a backend dimension, so a user can hold one credential per backend and a
ciphertext cannot be relabelled as another backend's.

## Date

2026-07-08 (recorded retrospectively 2026-07-10 from the session/vault record)

## Context

Issue writes went through one shared `REDMINE_API_KEY` — which was in fact a
team member's **personal** key. Every note and status change was attributed to
that person in Redmine's own journal, with only a text footer naming the real
actor. Attribution lived in prose instead of the system of record, and the
shared key's blast radius was one person's whole Redmine account.

## Decision

Each user provides their **own API key** through a credential-enrollment
endpoint. The gateway verifies the key belongs to that user (an identity call on
the key itself, email-matched), then stores it **AES-256-GCM encrypted at rest,
keyed and AAD-bound to the actor and backend** (a ciphertext moved to another
actor's or backend's slot will not decrypt). Issue **writes run with the caller's
own key — enforced**: no personal key means the write fails loudly with an
actionable message saying where to enroll; reads are unaffected. Tri-state key handling (missing / ok /
undecryptable) plus a boot guard: enforce-mode with no keystore refuses to
start rather than silently falling back to the shared key.

## Alternatives Considered

### Shared service key + attribution footer (status quo)

- Pros: zero user onboarding.
- Cons: journal author is wrong forever; the footer is prose, not identity;
  one personal key held server-side for everyone.
- Rejected — kept only as the pre-migration state.

### Backend sudo / switch-user impersonation

- Pros: no per-user key collection.
- Cons: requires an **admin** key on the gateway (strictly larger blast
  radius) and impersonation semantics that audit reviewers dislike.
- Rejected.

### Clients hold their own personal keys

- Pros: no server-side custody.
- Cons: sprays the secret into every agent config on every machine — the exact
  sprawl the gateway exists to remove.
- Rejected.

## Consequences

- The tracker's own record now shows the true author; the gateway's attribution
  footer shrinks to the audit id.
- Every writer has a one-time onboarding step; until then their writes fail
  loudly — a deliberate trade against silent misattribution.
- New operational surface: master-key custody, a `degraded` health flag when
  the master key is absent, offboarding purge of stored keys.

## Enforced By

`tests/test_redmine_keystore.py` (AAD binding, tri-state, enforce-mode boot
and write guards) and the `build_server` boot guard in
`src/mcp_governance_gateway/server.py`.
