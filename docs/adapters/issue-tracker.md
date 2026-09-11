# Issue Tracker Adapter

The issue tracker adapter exposes a stable tool surface over an internal issue
tracking backend such as Redmine.

## Tool Surface

| Tool | Operation | Description |
|---|---|---|
| `issues.get` | read | Return one issue by id |
| `issues.search` | read | Search issues by project/status/assignee |
| `issues.mine` | read | Issues in the project assigned to the caller |
| `issues.categories` | read | The project's issue categories (Redmine only) |
| `issues.create` | write | Create an issue with controlled fields |
| `issues.add_note` | write | Add a progress or analysis note |
| `issues.update_status` | write | Update status and completion fields |

## Stable Issue Shape

```json
{
  "id": "12345",
  "projectId": "example-project",
  "subject": "Issue title",
  "status": "IN_PROGRESS",
  "tracker": "BUG",
  "priority": "high",
  "dueDate": "2026-09-30",
  "assignee": {
    "id": "user-id",
    "displayName": "User"
  },
  "updatedAt": "2026-06-23T00:00:00Z"
}
```

## Write Attribution

Initial recommended mode:

- Use a dedicated gateway service account.
- Include actor, project, and gateway audit id in every created issue, note, or
  status update.
- Restrict the service account to the smallest project and operation set that
  supports the rollout.

Later mode:

- Store or exchange per-user downstream credentials only after the gateway has
  SSO, a hardened secret store, clear rotation, and incident response.
- Execute downstream writes as that user where the backend supports it.

The trade-off is native attribution versus credential blast radius. Per-user
downstream credentials give better backend history, but a gateway compromise can
expose or misuse many users' credentials. Service-account writes have weaker
native attribution, but the credential surface is smaller and easier to rotate.

Every write response should include enough normalized data for the audit log to
correlate the gateway actor with the backend change.

## Validation

- Validate tool input schemas before adapter calls.
- Validate backend responses before returning MCP output.
- Normalize backend-specific status names.
- Do not expose backend stack traces or raw errors.
- Deny destructive operations unless a separate security review approves them.

## Phase 1 Implementation

Implemented as `RedmineHttpBackend` (`src/mcp_governance_gateway/issue_backend.py`),
wired into the gateway as the `issues.*` tools. Status: built and unit-tested;
read paths validated read-only against a live Redmine. Deployment is gated on the
gateway host being able to reach Redmine.

- **Tenant boundary.** Each token carries an `issue_project` claim (Redmine project id
  or identifier). The gateway resolves it to a numeric project id and forces every
  operation to it: `issues.search` is constrained to that project, and
  `issues.get` / `issues.add_note` / `issues.update_status` first verify the target
  issue belongs to it (an id from another project returns 404). The client never
  supplies a project. Policy denies all `issues.*` for a token without a
  `issue_project` (the legacy `redmine_project` spelling is still read, ADR-0012).
- **Authorization (read vs write).** Read tools (`issues.get` / `issues.search` /
  `issues.mine` / `issues.categories`)
  need only an `issue_project`. Write tools additionally require the token to
  carry the `issue_writer` role; without it writes are denied (default-deny —
  confirmation is not authorization). `tools/list` advertises only the tools a
  principal may call (backend configured, `issue_project` present, and the write
  role for writes), though `handle_tool_call` re-checks policy regardless.
- **Writes are confirmation-gated** (ADR-0003). `issues.create`, `issues.add_note`,
  and `issues.update_status` are non-destructive writes: the first call returns a
  **single-use**, short-lived `confirmationId` bound to actor, project, tool, and
  arguments; the client re-calls with `confirm` to commit. The token is consumed on
  commit, so it cannot be replayed to repeat the write. Destructive suffixes stay
  denied.
- **Normalization.** Responses are mapped to the stable shape above; status and
  tracker names are normalized to UPPER_SNAKE. `update_status` and the
  `issues.search` status filter map a normalized name back to a status **id read
  from the instance** (`GET /issue_statuses.json`, cached, refetched once on a
  miss so a status added by an admin becomes usable without a restart). Status ids
  are per-instance — a fixed table would silently write the issue into some other
  instance's state, since any valid id succeeds — and resolving by name means an
  instance's custom statuses work with no configuration. An unknown name is
  rejected with the list this instance actually offers.
- **Write fields.** Beyond subject/description/status, `issues.create` and
  `issues.update_status` accept `assignee` and the optional planning fields
  `startDate` / `dueDate` / `priority` / `parentIssue` / `category` (Redmine only — the GitLab
  backend refuses them by name rather than dropping them silently). All of them are
  part of the confirmation binding, so a field cannot be swapped between the
  prepare and commit calls. `tracker` and `priority` are resolved by name from the
  instance, like statuses; `category` is resolved per project and read live, because
  categories are member-editable and a cache would serve a stale list. `parentIssue`
  is resolved through the project-scoped read first: Redmine would otherwise parent
  an issue onto another project's, which both crosses the tenant boundary and turns
  the field into an existence oracle.
  Both dates must be real calendar dates in `YYYY-MM-DD` form; validation errors
  identify the invalid field. Read rows, including `issues.mine` and `issues.get`,
  include `priority` as a lower-case name or null and `dueDate` as a date or null.
  GitLab returns null priority and passes through its due date on reads, while
  refusing every planning input (`startDate`, `dueDate`, `priority`, `parentIssue`, `category`) on writes.
- **`issues.mine` never answers from the shared credential.** `assigned_to_id=me`
  on the shared service key resolves to the service account, so the tool would
  return *its* issues as the caller's. It therefore requires the caller's own
  enrolled credential and fails loud without one, regardless of the
  enforce-personal-key setting — that flag governs write attribution, while this is
  a read whose entire meaning is the caller's identity.
- **Credential enrollment.** When a caller must enroll (or re-enroll) their own
  key, the error names the action and, if `CREDENTIAL_PORTAL_URL` is configured,
  where to do it. The gateway never hardcodes a host: with the variable unset the
  message carries no URL rather than pointing at somewhere that does not exist.
- **Credentials.** Two kinds. The shared backend key (`REDMINE_API_KEY` /
  `GITLAB_TOKEN`, server-side in `gateway.env`) serves reads and, unless
  `REDMINE_ENFORCE_PERSONAL_KEY` / `GITLAB_ENFORCE_PERSONAL_KEY` is on, writes by callers who have not enrolled.
  A caller who has enrolled a personal key in the keystore writes under it —
  including the existence check that gates `add_note` / `update_status`, so the
  shared key never vouches for an issue the caller's own account cannot read.
- **Native attribution.** A write on the shared key stamps
  `[via mcp-governance-gateway | actor=<actor> | audit=<id>]` into the tracker
  text — the new issue's description, an added note, and a journal note on a
  status change — so the record itself shows who acted through the gateway. A
  write on a personal key is already attributed natively, so the stamp is
  trimmed to `[via mcp-governance-gateway | audit=<id>]`. The gateway audit log
  remains authoritative either way.
- **Config.** `REDMINE_BASE_URL` / `REDMINE_API_KEY` / `REDMINE_TIMEOUT_SEC`, or
  the `GITLAB_*` equivalents with `ISSUE_BACKEND=gitlab` (ADR-0013). The backend
  is inert — its tools are not advertised — until its base URL is set. Every
  variable is listed in [`.env.example`](../../.env.example).
