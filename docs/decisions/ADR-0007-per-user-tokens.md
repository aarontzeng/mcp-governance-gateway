# ADR-0007: One Token per User per Project, Keyed on an Immutable Id

## Status

Accepted

## Date

2026-07-02

## Context

A shared per-project token makes every collaborator's agent identical. Audit says
"the project did it", memory records carry no author, and revoking one person
means rotating everyone.

Keying people by email instead is fragile in a different way: addresses are
mutable, so a rename breaks every history join; they are case-inconsistent; and
an address is only as trustworthy as whatever supplied it. A self-reported
identity can be claimed by whoever holds a token.

## Decision

Mint **one token per user per project**. The token's actor is an **immutable id**
supplied by whatever mints it, and that id must be **verified** at mint time —
taken from a signed identity assertion, not from a self-reported field. An email
address is kept as a display label only.

The token itself carries no claims. It is an opaque handle resolved server-side,
so re-scoping a token needs no re-mint and the string leaks nothing if seen.

The token store is per-user, may span several files (a static operator-managed
one plus a runtime-managed one), and is reloaded on change — keyed on
`(mtime, size, inode)`, because an atomic write swaps the inode and two writes in
one coarse-mtime tick would otherwise be indistinguishable, leaving a revoked
token authenticating. Writes to it must be atomic.

Minting is out of scope for this project. What it requires of a minter is the
above: a verified immutable id, and an atomic write.

## Alternatives Considered

### Keep shared per-project tokens

- Pros: simplest; fewest moving parts.
- Cons: no attribution, no per-person revocation.
- Rejected: attribution is the point.

### Key actors by email

- Pros: human-readable everywhere.
- Cons: mutable (renames break history joins), case-inconsistent, and only as
  trustworthy as its source.
- Rejected as the key; kept as a label.

### Identity forwarded per-request by a front gateway

- Pros: no token store.
- Cons: requires a front gateway on the data path, which ADR-0006 removed.
- Rejected as the primary mechanism; still supported as an optional signed
  assertion (ADR-0004).

## Consequences

- Per-person audit, memory actor stamps, and revocation of one person rather
  than rotation of a project.
- Adopting this on a deployment with shared tokens is a cutover: every
  pre-existing token is re-minted against the new key.
- Human-facing surfaces have to map the id back to a readable label, and any
  "my records" view has to match the union of {id, email} to span the cutover.
- The token store is part of the security boundary. Bind-mount its **directory**,
  not the file — an atomic replace swaps the inode, and a file mount would stay
  pinned to the old one.
