# ADR-0015: Full Git History for Document Author Provenance

## Status

Accepted; amends [ADR-0011](ADR-0011-per-project-docs-corpus.md)

## Date

2026-07-15

## Context

`docs.get` already returns the document's date and the corpus snapshot commit.
Readers also need to know who originally created a document and who last changed
that specific file.

Neither frontmatter nor the corpus HEAD can answer this reliably. Frontmatter
is author-controlled prose and may be absent; the HEAD author may have changed
an unrelated file. ADR-0011's depth-one clone also lacks the older commits
needed to identify the first commit that touched a path.

## Decision

Keep complete Git history in each server-side docs clone. Upgrade an existing
shallow clone in place with `git fetch --unshallow` on its next refresh, then
continue with ordinary branch fetches.

During snapshot construction, read the repository log once and derive, for
each served Markdown path, the author name from the first and latest commits
that touched that current path. Add the optional, backward-compatible
`createdBy` and `updatedBy` fields to `docs.get`. Author email is not exposed.

These fields describe Git commit provenance. They do not use the gateway's
polling identity, and they do not imply that the creator or updater currently
owns the document.

## Alternatives Considered

### Frontmatter `author` / `updated_by`

- Pros: no repository-history requirement.
- Cons: optional, manually maintained, and can drift from reviewed commits.
- Rejected as provenance; frontmatter remains document content.

### Corpus HEAD author

- Pros: available in a shallow clone.
- Cons: attributes every document to whoever made the repository's latest,
  potentially unrelated change.
- Rejected as incorrect.

### Query the hosting service's API for each document

- Pros: could expose account display names and review metadata.
- Cons: adds an online API dependency, per-document requests, permission
  coupling, and another failure mode to what is otherwise a passive mirror.
- Rejected; Git is the canonical merged history and it is already local.

## Consequences

- Initial clone and the one-time shallow-clone upgrade transfer more history
  and consume more disk. Docs repos are deliberately small reviewed-text
  corpora, so this is bounded and avoids a new service dependency.
- Names are exactly the commit author names, so where a deployment commits under
  an opaque id that is what appears. Mapping it to something readable is a
  display concern, handled with the same actor labels the memory listings use.
- A delete-and-recreate at the same path is treated as one path history;
  renaming a document starts provenance at its current path.
- Older gateways and other clients continue to work because the response
  fields are additive and optional.

## Enforced By

`tests/test_docs_backend.py` verifies first/latest author attribution, in-place
shallow-clone upgrades, and — as a regression guard on the reason this ADR
exists — that a shallow clone attributes every file to the tip author.
