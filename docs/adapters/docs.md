# Docs Corpus Adapter

Read-only `docs.search` / `docs.get` over **one docs repo per project**
(ADR-0011). Tenancy = repo = the token's `project` claim; no extra role.

## Backend contract

The backend is a git repo, not an HTTP service:

- Config: `DOCS_REPOS_FILE` (JSON, `{"<project>": {"url": ..., "branch": ...}}`),
  `DOCS_CLONE_DIR`, `DOCS_PULL_INTERVAL_SEC` (default 300). Docs tools are
  enabled only when file + dir are both set, and advertised only to tokens
  whose project has an entry. The repos file is re-read when it changes
  (mtime/size/inode), so adding or retargeting a project needs no restart; a
  corrupt or partial write keeps the last-good map rather than taking every
  project's docs tools down.
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
| `docs.list` | — | `documents[] {path,title,updated}` plus `status`/`staleAfter`/`decisionStatus` where declared, `commit`, `count` |

`commit` is the corpus snapshot sha — cite it when quoting a document.

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
| `docs.create` | `path`, `content`, `message`, `confirm` | Opens a pull request adding a new document. Refuses a path that already exists |
| `docs.update` | `path`, `content`, `message`, `sha`, `confirm` | Opens a pull request revising one. `sha` is what `docs.get` returned; a document that moved is a **409**, not an overwrite |
| `docs.review_comment` | `change`, `body`, `confirm` | A plain comment on a proposal, stamped with the gateway footer |
| `docs.review_get` | `change` | One proposal's state, title, url and whether it is merged |

All three writes are confirmation-gated and secret-scanned, need the
`docs_writer` (or `docs_reviewer`) role, and go out under the **caller's own
credential** for that host — enrolled in the credential store as backend
`docs-github`. There is no shared account and no fallback: a caller who has not
enrolled gets a 428 saying so. A proposal may only name a document the read path
would serve (under a served directory, ending in `.md`), so these tools cannot
propose a workflow file or a source file.

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
