# Security Model

> **What this document is.** Parts of it specify the target model rather than
> today's behaviour — the "must" and "should" statements are requirements on the
> design, not claims about this release. The gaps that matter most, stated plainly
> so nobody has to infer them from source:
>
> | Specified here | Implemented in this release |
> |---|---|
> | OIDC/OAuth with the gateway as resource server | **Yes, optionally** (ADR-0016). An opaque bearer resolved against the token file is still the default and is tried first; a bearer the file does not know is verified as an OIDC access token when `OIDC_ISSUER` is set. |
> | Audience-bound tokens, `aud`/`exp` validation | **For OIDC tokens, yes** — `iss`, `aud`, `exp`, `nbf`/`iat` and an algorithm allow-list, with `OIDC_AUDIENCE` required and no default. For opaque tokens there are still no claims to validate; scoping lives server-side. |
> | Signed assertions with `iss`/`aud`/`exp`/`jti` and an asymmetric key | **Partly.** Identity propagation verifies an HMAC over `user_id:email` only — no issuer, audience, expiry or replay id, and a missing header falls back to the token's own actor. Treat it as an attribution override, not an authentication hop. |
> | Role-based authorization per project | **Partly.** See "Authorization as implemented" below. |
>
> Everything a deployment relies on that is *not* in the right-hand column has to
> come from whatever mints the tokens and from the network boundary in front of
> this process.

## Authorization as implemented

The token's `roles` gate two things: issue **writes** require `issue_writer`,
and starting a CI build requires `ci_runner`. Everything else is tenancy, not
role:

| Tools | Requires | Confirmation |
|---|---|---|
| `memory.*` (including every write) | a `project` claim | **No** |
| `issues.get` / `search` / `mine` / `categories` | an `issue_project` claim | No |
| `issues.create` / `add_note` / `update_status` | `issue_project` + `issue_writer` role | Yes |
| `docs.*` (read-only) | a docs corpus configured for the project | No |
| `ci.status` / `ci.builds` / `ci.log` / `ci.artifact` | the project present in `CI_JOBS_FILE` | No |
| `ci.rerun` | the job present in `CI_TRIGGER_JOBS_FILE` **and** the `ci_runner` role | Yes |
| any tool whose name ends in delete/destroy/purge/remove | — | Denied outright |

The consequence worth stating out loud: **a token with a project can append to
that project's shared memory, lessons and actions.** Those stores are
team-visible and append-only, so "read-only agent" is not something a token can
express for memory today. If you need that distinction, do not give the agent a
project token.

## Principles

- Validate every external input at the gateway boundary.
- Default to deny when policy is absent or ambiguous.
- Deny rules override allow and confirmation rules.
- Do not pass MCP client tokens to downstream services.
- Keep downstream credentials server-side.
- Log decisions, not secrets.
- Treat tool metadata and downstream content as untrusted.
- Treat identity headers as untrusted unless the request path is authenticated.
- Fail closed for writes.

## Authentication

Two authenticators may run at once, and the **token file is consulted first**.
A bearer it does not know is then verified as an OIDC access token when
`OIDC_ISSUER` is configured (ADR-0016). That order is deliberate: an
operator-issued token stays authoritative, and a JWT can never shadow an entry
in the file.

The OIDC path takes only the identity. `sub` becomes the actor — the verified,
immutable id ADR-0007 asks a minter for — and `email` stays a display label.
`project`, `issue_project` and `roles` come from a grants file **this
deployment owns**, resolved by subject and then by group; a `project` or `roles`
claim inside a token is ignored. Where the `groups` map is used, the IdP's group
claim does select *which* grant applies — the token chooses from a menu this
deployment wrote, and cannot add to it. A deployment that wants no such
influence lists subjects instead (ADR-0016). A subject row is an override, not
an addition: when one matches, groups are not consulted, so an explicit row with
empty roles takes away what the groups would have given. A subject with no grant
is authenticated and has no project, which every tool then denies.

Two verification rules do not bend: the signature algorithm comes from an
allow-list in code (`alg: none` and every HMAC algorithm are refused *before* a
key is looked up, because a JWKS publishes public keys), and the audience is
checked against a required `OIDC_AUDIENCE` with no default. A half-configured
OIDC block is refused at boot rather than silently disabled.

An IdP outage keeps the last-good key set rather than revoking everyone, the
same posture the token file's hot reload already takes.

Where no IdP is available, per-user gateway tokens remain the supported path,
minted by `mcpgw-admin`. They do **not** expire on their own — nothing in the
opaque path validates a lifetime — so rotation is an operator action
(`mcpgw-admin rotate`) and revocation is removing the entry.

Gateway tokens must be audience-bound to the gateway endpoint. Tokens issued for
other resources must be rejected.

### Pilot Gateway Tokens

Pilot tokens are different from backend API keys:

- They are scoped to the gateway, not to a downstream backend.
- They are audience-bound to the gateway endpoint.
- They carry actor, project, and role claims or map to them server-side.
- They are short-lived or explicitly revocable.
- They are stored in user-local secret storage or environment variables, not in
  project repositories.
- They can be rotated without rotating issue tracker or memory backend secrets.

## Gateway-to-Adapter Identity

If a front gateway (a reverse proxy / identity-forwarding front end) forwards identity
to the gateway, the adapter must authenticate the gateway-to-adapter hop before trusting
actor or tenant values.

Plain headers such as `x-user-id`, `x-tenant-id`, `x-project-id`, or
`x-request-id` are not an authentication mechanism. They are acceptable only as
an internal representation after one of these controls is in place:

- adapter is reachable only from the gateway over loopback or a private service
  network
- firewall or container network policy blocks ordinary client sources
- mTLS authenticates the gateway to the adapter
- gateway sends a signed identity assertion that the adapter verifies

For the pilot, prefer network isolation (the first two controls): it is the
cheapest sufficient control when the adapter and front gateway share a private
network. Add mTLS or a signed assertion only when that hop can cross an untrusted
network, since a signed assertion adds an asymmetric key pair to manage and
rotate: the gateway holds the private signing key and the adapter holds only the
public verification key.

Either way, the adapter's actor and project attribution is only as trustworthy as
the front gateway's authentication: the front gateway is part of the trusted
computing base. The adapter verifies that a request came from the gateway, not
that the end user is who the gateway claims, so the front gateway's identity
provider and session handling must be correspondingly trusted and audited.

Recommended signed assertion fields:

```json
{
  "iss": "front-gateway",
  "aud": "mcp-governance-gateway",
  "sub": "user@example.com",
  "project": "example-project",
  "roles": ["developer"],
  "requestId": "req_...",
  "iat": 1782199000,
  "exp": 1782199300,
  "jti": "assertion_..."
}
```

In network-isolation mode the adapter authenticates the hop by source, not by
assertion: it accepts requests only from the trusted gateway (loopback, private
network, or mTLS) and ignores client-supplied identity headers.

When signed assertions are enabled, the adapter must reject missing, expired,
wrong-audience, replayed, or signature-invalid assertions. Use an asymmetric
signature (for example RS256 or ES256) so the gateway keeps the private signing
key and only the public verification key is distributed to the adapter and
rotated on a defined schedule; a shared HMAC secret does not give the adapter a
verification-only key, so avoid it for this boundary.

In both modes, ingress must strip external identity headers before the gateway
re-creates trusted values.

## Authorization

Policy decisions use:

- actor user id
- actor groups and roles
- project id
- tool name
- operation class: read, write, destructive
- target backend
- resource id

### Policy Semantics

The policy engine must be deterministic:

1. If no rule matches, the decision is `deny`.
2. If any matching rule says `deny`, the decision is `deny`.
3. `allow` applies only when there is no matching `deny`.
4. `require_confirmation` applies only when there is no matching `deny` and the
   operation is eligible for confirmation.
5. Destructive operations are not confirmation-eligible in the MVP. They are
   denied until there is a separate product and security review.

The internal tools adapter must re-enforce these same semantics even when a
front gateway already applied RBAC. This is defense in depth and keeps
domain-critical writes safe if gateway policy, token revocation, or user lookup
behavior is misconfigured or degraded.

Example policy result:

```json
{
  "decision": "require_confirmation",
  "reason": "issue tracker write operation",
  "confirmationTtlSec": 300
}
```

## Confirmation Strategy

Confirmation is a mistake-prevention control, not a trustworthy defense against
a malicious client. A client can omit the confirmation UX or lie about user
approval. For truly dangerous operations, the only reliable MVP policy is
`deny`.

The preferred mechanism is MCP elicitation when the client declares support for
the elicitation capability. The gateway asks the client to present a non-secret
confirmation summary to the user, then proceeds only if the client returns the
expected approval response.

Elicitation must not request secrets, API keys, passwords, raw tokens, or other
sensitive values. It is only for confirming a bounded action summary such as:

```text
Add note to issue 12345 in project example-project as actor user@example.com.
```

Fallback for clients without elicitation support is a two-step tool contract:

1. `tool.prepare_*` returns a normalized action summary and confirmation id.
2. `tool.commit_*` executes only with the confirmation id.

Confirmation ids must be bound to:

- actor
- project id
- tool name
- target resource id
- normalized arguments hash
- request id
- short expiry time

The gateway must reject stale, replayed, mismatched, or cross-actor
confirmation ids.

## Downstream Secret Strategy

Initial issue tracker writes should use a dedicated service account and include
the real actor plus gateway audit id in the created note or update body. This
keeps native issue tracker attribution less precise, but limits the blast radius
to one controlled credential.

Per-user downstream credentials provide better native backend attribution, but
they turn the gateway secret store into a collection of every user's backend
credential. They should wait until the gateway has SSO, a hardened secret store,
clear rotation, and incident response procedures.

Memory backend credentials remain server-side only. Clients never receive the
memory backend secret.

## Backend Isolation

Gateway policy is meaningful only if clients cannot bypass it. After the gateway
is active for a backend, direct client access to that backend must be closed.

For the internal adapter and memory backend this means:

- The adapter and backend listen only on loopback or a private network reachable
  by the expected upstream component.
- Firewalls or container network rules reject non-gateway and non-adapter
  sources.
- Existing direct SSH tunnel instructions are retired for normal users.
- Backend credentials are rotated after migration to the gateway/adapter path.
- Verification includes direct client probes to both adapter and backend that
  must fail.

Viewer or admin access must be handled as a separate privileged path with its
own authentication and audit expectations.

## Audit

Audit events must include:

- timestamp
- request id
- actor
- project id
- tool name
- resource id
- policy decision
- confirmation method when used
- backend status
- duration

Audit events must not include:

- access tokens
- backend API keys
- raw prompts
- unredacted sensitive memory content

## Threats

| Threat | Control |
|---|---|
| DNS rebinding against local MCP servers | Remote gateway over HTTPS, Origin validation |
| Token reuse against wrong service | Audience validation |
| Client token passed to backend | Separate downstream credentials |
| Prompt injection in issue text | Treat backend text as untrusted content |
| Accidental write tool call | Elicitation or two-step confirmation |
| Malicious client claims false approval | Deny dangerous operations; do not treat confirmation as an auth boundary |
| Forged actor or tenant header | Adapter isolation, mTLS or signed gateway assertion, ingress header stripping |
| Direct adapter or backend bypass | Adapter/backend isolation, firewall rules, secret rotation |
| Shared memory cross-project leakage | Gateway-enforced project namespace |
