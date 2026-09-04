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

**The IdP supplies `sub` → `actor`, and nothing else that matters.** `email`
stays a display label, as ADR-0007 already requires. `project`,
`issue_project` and `roles` come from a **grants file this deployment owns**,
resolved by subject and then by group. A `project` claim inside a token is
ignored.

That is the load-bearing half. An IdP knows who someone is. It does not know
which tenant of *this* gateway they may act in, and a `project` claim minted
elsewhere would make our tenant boundary a function of somebody else's client
configuration — including, on a shared IdP, of a client we do not administer.
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

**`token_id` is derived from `iss|sub`, not from the token string.** An access
token is refreshed every few minutes. The confirmation store binds a pending
write to the principal's `token_id`, and binding it to the token *instance*
would expire every pending confirmation the moment a client refreshed — while
protecting nothing the identity binding does not already protect.

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
- Rejected. The verification is ~120 lines and the parts worth getting right
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
