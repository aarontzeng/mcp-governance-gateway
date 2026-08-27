# ADR-0011: Per-Project Docs Repo as the Read-Only Docs Corpus

## Status

Accepted

## Date

2026-07-10 (container/taxonomy decided 2026-07-09; see the docs-corpus plan)

## Context

Roadmap Phase 7 asks for "Documentation search": agents need the project's
descriptive documents (reports, analyses, session notes) without depending on
one person's machine. The candidate corpora were a personal Obsidian vault, a
central docs monorepo, Redmine wiki/attachments, and per-project git repos.
Separately, a taxonomy was settled: **normative** docs (ADRs, architecture
contracts, agent rules, OWNERS) stay in the code repo, in the agent's worktree.

## Decision

One **docs repo per gateway project** (e.g. `myproject-docs`), hosted on the
project's code platform and merged via review. The gateway serves it read-only
as `docs.search` / `docs.get`: a server-side map `project → repo URL`, a
throttled shallow-clone pull loop, and a stdlib BM25 index (ASCII words + CJK
bigrams) over markdown in `raw/` and `wiki/` only. **Tenancy = repo = the
token's `project` claim** — no new role. `docs.get` answers purely from the
in-memory index, so an unserved-but-present path is indistinguishable from a
nonexistent one (no existence oracle). No LLM compile step in v1; `wiki/` pages
are hand-written. Results carry the corpus commit sha for citation.

## Alternatives Considered

### Personal Obsidian vault as corpus

- Pros: content already exists.
- Cons: bus factor 1, external personal hosting, mixed personal/project
  content, zero tenant signal, high blast radius.
- Rejected (audited; see the docs-corpus plan).

### Central docs monorepo

- Pros: one clone, one index.
- Cons: tenancy degrades to folder filtering enforced only by the gateway,
  instead of repo ACLs.
- Rejected.

### Redmine wiki / attachments

- Pros: zero new repos; existing adapter surface.
- Cons: no review/diff/provenance; attachments fork and rot.
- Rejected as corpus; tickets keep summary notes + pointers.

### Vector index for docs

- Pros: semantic recall.
- Cons: agentmemory already owns semantic search; a second embedding stack for
  reviewed prose duplicates infrastructure.
- Rejected — BM25 first, revisit only on demonstrated need.

## Consequences

- The corpus is empty until teams commit docs; a project without a configured
  repo simply doesn't see the docs tools (`tools/list` hides them; policy still
  re-checks on call).
- New ops surface: read-only deploy keys per docs repo, clone dir, pull
  interval; a pull failure serves the last snapshot rather than failing reads.
- The LLM-compiled `wiki/` (v2) stays gated on a working compiler-idempotency
  design, per the reviewed plan.

## Enforced By

`tests/test_docs_backend.py` (tenant isolation through the gateway, the
existence-oracle equivalence, refresh behavior, CJK/BM25 search).
