# Docs Corpus Adapter

Reads and reviewed proposals over **one docs repo per project**
(ADR-0011). Tenancy = repo = the token's `project` claim; reads need no extra role.

## Backend contract

The backend is a git repo, not an HTTP service:

- Config: `DOCS_REPOS_FILE` (JSON, `{"<project>": {"url": ..., "branch": ...}}`),
  `DOCS_CLONE_DIR`, `DOCS_PULL_INTERVAL_SEC` (default 300). Docs tools are
  enabled only when file + dir are both set, and advertised only to tokens
  whose project has an entry. The repos file is re-read when it changes
  (mtime/size/inode), so adding or retargeting a project needs no restart; a
  corrupt or partial write keeps the last-good map rather than taking every
  project's docs tools down. Repository URLs must be unique across projects
  (case-insensitive); duplicate mappings are rejected to preserve corpus isolation.
- The gateway keeps a clone per project, refreshed at most once per interval on
  access.
- **A snapshot belongs to a specification, not just to a moment.** Each snapshot
  records the `(url, branch)` it was built from, and is only reused while that
  still matches the current one — so retargeting a project takes effect on the
  next call rather than after the pull interval expires, and the clone's origin is
  retargeted at the same time. The key is deliberately the url/branch pair and not
  a registry version, so editing one project does not force every other project to
  refetch.
- **A fetch failure serves the last snapshot only for the same specification.** A
  hiccup against the same repository yields stale content, which is a reasonable
  trade. A *new* specification whose first fetch fails yields 503: the previous
  snapshot is a different corpus, and serving it under the new specification would
  answer the wrong question rather than admit it cannot answer. The clone keeps **full
  history**: per-file provenance needs the first commit that touched a path, and
  in a shallow clone the grafted tip looks like the commit that introduced every
  file — which yields a confidently wrong author, not a missing one. A clone left
  shallow by an earlier release is upgraded in place on the next refresh.
- Served set: `raw/**/*.md` and `wiki/**/*.md`, excluding any dot-path.
  Frontmatter (`title`, `date`/`updated`) feeds result metadata; a flow-style
  list (`tags: [a, b]`) is parsed as a list rather than handed back as the
  literal string.

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `docs.search` | `query` (≤512 chars), `limit` (1–25, default 8) | `results[] {path,title,snippet,updated,commit,score}`, `commit`, `count` |
| `docs.get` | `path` (as returned by search) | `path,title,frontmatter,text,commit`, plus `createdBy`/`updatedBy` when the log has them |
| `docs.lint` | — | `findings[]`, `commit`, `count`; available on read-only corpora |
| `docs.list` | — | `documents[] {path,title,updated}` plus `status`/`staleAfter`/`decisionStatus` where declared, `commit`, `count` |

`commit` is the corpus snapshot sha — cite it when quoting a document.

`docs.lint` reports missing titles (neither nonempty frontmatter title nor a
heading), broken relative `.md` links into the served snapshot, and duplicate
case-insensitive slugs (explicit `slug`, otherwise the full path without `.md`).
Findings use `kind`: `missing_title` with `path`, `broken_link` with `path` and
`target`, or `duplicate_slug` with `slug` and `paths`. External and absolute links
are skipped. This is read-only advice, not a publication verdict or a check of
remote URLs, template versions, or deployment-specific naming conventions.

**Lifecycle signals on `docs.list`.** A document may declare `status`,
`stale_after` and `decision_status` in its frontmatter; the listing passes them
through so a reader can skip a deprecated or expired document without fetching
it. Absent means nothing is claimed — the gateway does not substitute a default,
and staleness stays a raw date so each consumer compares it against its own
today.

**Provenance.** `createdBy` / `updatedBy` come from the Git log — the first and
most recent commits to touch that path — because a document cannot forge its own
history the way a frontmatter `author:` line can. An opaque author key (an
employee id, where a deployment re-keyed identities) is mapped through the same
token store the memory listings use, so both name the same person the same way.

## Search

Stdlib BM25 (k1=1.5, b=0.75) over ASCII word tokens plus CJK unigrams and
bigrams. Deliberately not a vector index: agentmemory owns semantic search;
this corpus is reviewed prose (see ADR-0011 alternatives).

## Security notes

- Reads share the per-user read quota with memory reads, and every call is
  audited (actor / project / tool / outcome).
- **Existence oracle**: `docs.get` answers purely from the in-memory index —
  a path that exists in the repo but is not served (README, dotfiles) takes
  the same code path and returns the same error as one that never existed.
- The clone uses a read-only deploy key; the gateway never writes to the repo.

## Proposing a change (`docs.create` / `docs.update` / `docs.review_comment`)

Off unless the project's entry in `DOCS_REPOS_FILE` carries a `review` block:

```json
{"team-a": {"url": "https://github.com/org/handbook.git", "branch": "main",
            "review": {"type": "github", "repo": "org/handbook"}}}
```

`type` is `github` today. `api` defaults to `https://api.github.com` (set it for
GitHub Enterprise). `baseBranch` defaults to the branch the corpus is read from,
so the two cannot drift into proposing against something nobody reads. A
malformed block is a **boot error**: an operator who wrote one believes writes
are on.

| Tool | Arguments | Does |
|---|---|---|
| `docs.create` | `path`, `content` or `contentStaged`, `message`, `confirm` | Opens a pull request adding a new document. Refuses a path that already exists |
| `docs.update` | `path`, `content` or `contentStaged`, `message`, `sha`, `confirm` | Opens a pull request revising one. `sha` is what `docs.get` returned; a document that moved is a **409**, not an overwrite |
| `docs.review_comment` | `change`, `body`, `confirm` | A plain comment on a proposal, stamped with the gateway footer |
| `docs.review_get` | `change` | One proposal's state, title, url and whether it is merged |
| `docs.review_list` | `limit` (1–50, default 20) | Open proposals, newest updated first: `changes[] {number,title,author,updated,url,isAuthor}`, `count` |
| `docs.review_add_reviewer` | `change`, `reviewer`, `confirm` | Requests a GitHub account's review on an open proposal; returns `number`, `reviewer`, `reviewerAdded` |
| `docs.review_abandon` | `change`, optional `message`, `confirm` | Closes your own open proposal; returns `number`, `url`, `abandoned`; leaves its branch intact |
| `docs.asset_stage_url` | optional `kind` (`content` only, default `content`) | Mints an upload URL and `stagedId`; see the staging flow below |

Create, update and abandon require `docs_writer`; commenting and requesting a
reviewer require `docs_reviewer`. All five host writes are confirmation-gated;
document text, commit messages and comment bodies are secret-scanned. Prepare
without `confirm`, then repeat the same arguments with the returned confirmation
id in `confirm`. Requesting a reviewer changes the host's requested-reviewer
list, so its confirmation binds both `change` and `reviewer`. It is idempotent:
a reviewer already requested (case-insensitive account comparison) causes no
second host write. `reviewer` is a GitHub login of at most 39 characters.

Review listing and reading need no writer/reviewer role or confirmation.
`isAuthor` compares against the caller's enrolled host identity. Abandonment also
checks that identity against the proposal's author; another person's proposal
cannot be closed. An optional abandonment message is secret-scanned and stamped
as a comment before closure.

Review-host operations go out under the **caller's own credential** for that
host — enrolled in the credential store as backend
`docs-github`. There is no shared account and no fallback: a caller who has not
enrolled gets a 428 saying so. A proposal may only name a document the read path
would serve (under a served directory, ending in `.md`), so these tools cannot
propose a workflow file or a source file.

### Staged Markdown (`docs.asset_stage_url` → PUT → `contentStaged` → confirm)

Set `DOCS_ASSET_BASE_URL` to the public gateway base URL and route
`PUT /docs/asset-stage/<upload-token>` to the MCP listener. Staging is advertised
only for a configured review corpus and needs `docs_writer`. Minting and uploading
do not write to the review host and require no confirmation. Only UTF-8 Markdown
content is supported; this is not an image or general binary upload facility.

1. Call `docs.asset_stage_url` with `{"kind":"content"}`. It returns `url`, a
   `doc_`-prefixed `stagedId`, `expiresInSec: 60`, `singleUse: true`,
   `maxBytes: 2097152`, `kind: "content"`, and
   `allowedTypes: ["text/markdown; charset=utf-8"]`.
2. PUT the nonempty UTF-8 bytes to `url` within **60 seconds**, with the same
   gateway bearer token and a single `Content-Length` (no `Transfer-Encoding`).
   The maximum body is **2 MiB**, inclusive. The route uses the same signed
   identity propagation as `/mcp`; a front gateway must forward the same identity
   on both routes. Success is HTTP 201 with `stagedId`, `bytes`, and `type`.
3. Prepare `docs.create` or `docs.update`, passing `contentStaged: stagedId`
   instead of `content`, plus the usual path/message and, for update, `sha`.
   Passing both body forms is an error. Prepare checks ownership, expiry and
   uploaded content before issuing a confirmation id, and secret-scans the body.
4. Repeat those arguments with `confirm` set to that id. The immutable stage id
   binds the body without resending it. A successful host proposal consumes the
   stage; a failed proposal releases it for a fresh prepare/confirm attempt.

Ownership is the same `(actor, project, token_id)` key as confirmation. Only the
minting token can upload or use the stage: another bearer for the same actor and
project is refused, even though the PUT route has no separate role check. Foreign,
expired and consumed stages all return the same 404. A foreign bearer's attempt
does **not** consume the URL. The owner's first upload accepted for stage
validation consumes the URL even if body validation fails; transport refusals
before stage validation do not consume it.

An uploaded stage lasts **3600 seconds from upload**, independently of the URL's
60-second lifetime. Each actor may hold **16 pending or uploaded stages** and
**32 MiB of uploaded bytes**, shared across that actor's projects; exact-fit byte
usage is accepted. Exceeding a quota returns 429. Preparation does not consume a
stage; confirmation reserves it through the host call, so a competing claim
returns 409. There is no stage-delete tool: expiration and quotas bound retained
state. Stages and upload tokens live only in process memory and disappear on
restart.

### What actually carries the governance property

The gateway cannot merge: the interface a review host implements has no merge,
approve or push method, and a comment is a comment (verified: it creates no
review and leaves `reviewDecision` null, so it cannot satisfy a
required-approvals rule).

**That is a statement about the gateway, not about your repository.** If the
repository lets the proposer merge their own pull request unreviewed, an agent
holding that person's token has achieved a publish by asking them to click one
button. Two settings are what make the property real, and they are yours:

- require a pull request before merging, with at least one approving review
  **from someone other than the author**;
- give the enrolled token the narrowest scope that can open a pull request. A
  fine-grained token with Contents: read/write and Pull requests: read/write on
  that one repository is enough; it does not need admin, and it should not have
  workflow scope.

Abandoned proposal branches accumulate. Nothing here deletes them, because
deleting a branch is a write this interface deliberately cannot do.
