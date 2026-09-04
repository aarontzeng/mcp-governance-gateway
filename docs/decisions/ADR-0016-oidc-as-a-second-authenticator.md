# ADR-0016: OIDC as a Second Authenticator, with Tenancy Kept Out of the Token

## Status

Accepted

## Date

2026-09-04

## Context

ADR-0007 requires a token's actor to be an immutable id **verified at mint
time, taken from a signed identity assertion rather than a self-reported
field** — and then placed minting out of scope. Both halves were right, and
together they left an adopter hand-writing a JSON file of opaque tokens
before the gateway would answer anything. `.env.example` said so plainly:
"this gateway is not an OIDC resource server".

That sentence described a boundary, but it read as a principle, and it is not
one. An OIDC access token *is* the signed assertion ADR-0007 describes, minted
by something whose entire job is verifying who the holder is. Refusing to
verify one does not make the gateway stricter; it makes every deployment build
the minter ADR-0007 declined to specify.

The question this ADR settles is not whether to accept OIDC. It is **what an
IdP is allowed to decide**.

## Decision

Verify OIDC bearer tokens as a **second authenticator beside the token file**,
and take from them only the identity.

**The token file is consulted first.** A bearer that resolves there resolves
there, whatever its shape. This keeps an operator-issued token authoritative,
makes it impossible for a JWT to shadow a token-file entry, and means a
deployment that configures no OIDC variables behaves exactly as it did in
0.1.0. `GATEWAY_TOKEN_FILE` becomes optional only when `OIDC_ISSUER` is set,
because an IdP-only deployment has no opaque tokens to store.

**The IdP supplies identity. The grants file supplies tenancy.** `sub` becomes
`actor` and `email` stays a display label, as ADR-0007 already requires.
`project`, `issue_project` and `roles` come from a **grants file this deployment
owns**, resolved by subject and then by group. A `project` or `roles` claim
inside a token is ignored outright.

Be precise about what that does and does not buy, because the short version —
"tenancy never comes from the token" — is not quite true. Where a deployment
uses the `groups` map, the IdP's group claim **selects which grant applies**.
The token cannot invent a project, but it can choose from the menu this
deployment wrote. That is the distinction that matters: the set of reachable
projects, and the roles attached to each, are ours; which of them a given token
lands on is the IdP's. A deployment that does not want even that leaves
`groups` empty and lists subjects, which is why both maps exist.

The reason to keep the menu here rather than take a `project` claim outright: on
a shared IdP the client that mints those claims is often administered by other
people, and a mapper added there would silently become a tenant boundary here. A
group name we do not recognize resolves to nothing.

**A subject row is the whole answer, not an addition.** When a subject matches,
its groups are not consulted at all — so an explicit row with empty `roles`
takes away what the groups would have given. That is what "explicit override"
has to mean for it to be usable during an incident, and the example file says so
because it is the kind of thing that surprises people exactly once.

A subject with no grant is authenticated and has no project, which
`Policy.decide` already refuses: the fail-closed direction, reached without a
new code path.

**Two verification rules do not bend:**

- **The algorithm comes from our allow-list, never from the token.**
  `alg: none` and every HMAC algorithm are refused by name, before any key
  lookup. A JWKS publishes *public* keys; accepting HS256 would let anyone who
  can read it sign a token with the key it hands out. This is the oldest JWT
  bypass there is and it deserves an explicit refusal rather than an implicit
  one.
- **The audience is checked and has no default.** An issuer mints tokens for
  many audiences; accepting whatever arrives would let a token issued for an
  unrelated client act here. `OIDC_AUDIENCE` is required, and a half-configured
  OIDC block is refused at boot rather than silently disabled — an operator who
  set two of three variables believes the mode is on.

**Availability follows the token file's precedent.** The key set is cached, an
unknown `kid` triggers at most one refetch per cooldown, and a fetch failure
keeps the last-good keys and says so on stderr. An IdP outage must not revoke
everyone; a rotation must not become a stampede.

**`token_id` is derived from `iss|sub`, not from the token string**, and this
one is a real trade rather than a free win. An access token is refreshed every
few minutes while a confirmation lives for five, so binding a pending write to
the token *instance* would expire confirmations whenever a client refreshed —
a failure that would look random and would land on the write path.

What it costs: for an OIDC caller the confirmation is bound to the **identity**,
not to the credential. `confirm.py`'s identity key is
`actor | project | token_id | issue_project | tool`, and with `actor == sub` and
`token_id == f(iss, sub)` the credential drops out of it. A second session of the
same person — a refreshed token, a second agent they attached — can therefore
commit a confirmation the first one prepared, given identical arguments. It
gains no authority that session did not already have (it could call prepare
itself), but a `confirmationId` that leaks into a transcript or into un-gated
team memory becomes a *user*-level capability for its 300 seconds rather than a
credential-level one. `SECURITY.md` lists it among the known limitations rather
than leaving it to be found.

## Alternatives Considered

### Take project and roles from token claims

- Pros: no second file; an IdP admin can onboard a team without touching the
  gateway.
- Cons: the tenant boundary becomes a function of the IdP's client
  configuration, which on a shared IdP is administered by other people.
- Rejected as the source of truth. A claim-driven mapping remains possible as
  an explicit, per-deployment opt-in; the grants file wins where both exist.

### Replace the token file entirely

- Pros: one identity path instead of two.
- Cons: strands every 0.1.0 deployment and every environment with no IdP,
  including the single-operator case this project is often deployed as.
- Rejected: the two paths are cheap to run side by side.

### Require a front gateway to terminate OIDC (ADR-0004's signed headers)

- Pros: no JWT verification here at all.
- Cons: puts a component on the data path that ADR-0006 deliberately removed,
  and the existing header mechanism is HMAC-only with no `exp`, `aud` or
  replay protection — it is an attribution override, not an authentication hop,
  and its own documentation says so.
- Rejected as the primary mechanism; it remains supported and unchanged.

### Depend on PyJWT / python-jose

- Pros: less code to own.
- Cons: a dependency for something `cryptography` — already required for the
  credential store — verifies directly, in a project whose deployment story is
  "one process, one third-party dependency".
- Rejected. The verification proper is ~120 lines (the module is larger
  because it also carries the key cache, the grants file and discovery), and
  the parts worth getting right
  (the algorithm allow-list, the audience check, ECDSA's raw R||S encoding) are
  exactly the parts a library would hide.

## Consequences

- An adopter with an IdP configures a grants file and mints nothing.
- Onboarding a person is a grants-file edit, hot-reloaded like every other
  policy file here; offboarding is removing them from it, or from the IdP.
- Two subjects' group grants that name different projects are **refused**
  rather than merged: picking one would make a tenant boundary depend on
  iteration order.
- The gateway now makes an outbound call at boot (discovery) and periodically
  (JWKS). Boot fails loudly if discovery fails; runtime keeps last-good.
- `.env.example`'s "not an OIDC resource server" claim is withdrawn.
