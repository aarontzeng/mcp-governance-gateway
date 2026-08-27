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
