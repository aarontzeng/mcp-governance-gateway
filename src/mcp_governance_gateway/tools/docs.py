"""The docs family: a per-project reviewed corpus, and proposals against it.

Reads are over the project's reviewed docs repo; tenancy is the token's
project claim (the corpus map is keyed by project -- no role needed). Writes
PROPOSE: they open or revise a change on a review host under the caller's own
credential, and there is no tool that merges one (ADR-0017). Two roles because
they are different acts -- writing a document and giving an opinion on
someone else's -- and a deployment may well grant only the second.

The split is real HERE and not on the host: both roles resolve the same
`docs-<type>` credential, so a reviewer-only grant stops docs.create through
this gateway while the review host still sees one write-capable identity.
Giving the comment path its own credential slot would let a deployment enrol a
genuinely comment-only token; it would also make everyone enrol twice, so it
waits for someone who wants it (roadmap).
"""
from __future__ import annotations

from typing import Any

from ..auth import Principal
from ..docs_backend import DocsBackendError
from ..memory_backend import RequestContext
from ..secret_scan import find_secret
from . import args
from .base import (
    DOCS,
    DOCS_REVIEWER,
    DOCS_WRITER,
    FEATURE_DOCS,
    FEATURE_DOCS_REVIEW,
    FEATURE_DOCS_STAGE,
    REVIEW,
    WRITE,
    ToolHost,
    ToolSpec,
)
from .memory import reject_secret

_CORPUS = frozenset({FEATURE_DOCS})
_REVIEW_HOST = frozenset({FEATURE_DOCS, FEATURE_DOCS_REVIEW})
_STAGE = frozenset({FEATURE_DOCS, FEATURE_DOCS_REVIEW, FEATURE_DOCS_STAGE})
_CHANGE = {"type": "integer", "minimum": 1, "description": "The proposal number."}
_EMPTY = {"type": "object", "properties": {}, "additionalProperties": False}

TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="docs.search",
        family=DOCS,
        requires=_CORPUS,
        description=(
            "Keyword-search this project's docs corpus (reviewed markdown). Returns "
            "path/title/snippet/commit; full text via docs.get."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 25, "default": 8},
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="docs.list",
        family=DOCS,
        requires=_CORPUS,
        description=(
            "List every document in the docs corpus (path/title/updated, plus status/staleAfter "
            "when declared — a deprecated or stale document can be skipped without fetching it). "
            "Use docs.search for relevance."
        ),
        input_schema=_EMPTY,
    ),
    ToolSpec(
        name="docs.get",
        family=DOCS,
        requires=_CORPUS,
        description=(
            "Fetch one document by path (as returned by docs.search/docs.list): full text + "
            "frontmatter + the corpus commit, and who created and last changed it."
        ),
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="docs.lint",
        family=DOCS,
        requires=_CORPUS,
        description="Read-only findings for this project's corpus: broken relative Markdown links, missing titles and duplicate slugs. Findings are not a verdict.",
        input_schema=_EMPTY,
    ),
    ToolSpec(
        name="docs.create",
        family=DOCS,
        access=WRITE,
        role=DOCS_WRITER,
        requires=_REVIEW_HOST,
        description=(
            "Propose a NEW document as a change on this project's review host (two-step: call "
            "once for a confirmationId, then again with `confirm`). It does NOT publish — it "
            "opens a proposal under YOUR OWN identity for a person to merge or reject. Refused "
            "if the path already exists (use docs.update), if the path is not a .md file "
            "under a served directory, or if the body contains something credential-shaped. "
            "For long bodies, call docs.asset_stage_url(kind='content'), PUT the Markdown once "
            "with your bearer token, and use contentStaged instead of content in both calls."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path within the corpus, e.g. wiki/onboarding.md"},
                "content": {"type": "string", "description": "The whole document, including frontmatter."},
                "contentStaged": {"type": "string", "description": "A doc_ stagedId; mutually exclusive with content. Confirmation binds to this immutable body id."},
                "message": {"type": "string", "description": "Why, in one line. Becomes the proposal title."},
                "confirm": {"type": "string"},
            },
            "required": ["path", "message"],
            "oneOf": [{"required": ["content"]}, {"required": ["contentStaged"]}],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="docs.update",
        family=DOCS,
        access=WRITE,
        role=DOCS_WRITER,
        requires=_REVIEW_HOST,
        description=(
            "Propose a change to an EXISTING document (two-step, like docs.create). Send the "
            "`sha` that docs.get returned for it: if the document moved since you read it the "
            "proposal is refused rather than overwriting someone's edit. Opens a proposal under "
            "your own identity; publishing stays a human action. Refused if the body contains "
            "something credential-shaped. For long bodies, call docs.asset_stage_url(kind='content'), "
            "PUT the Markdown once with your bearer token, then use contentStaged instead of content "
            "in both prepare and confirm calls."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string", "description": "The whole document after your change."},
                "contentStaged": {"type": "string", "description": "A doc_ stagedId; mutually exclusive with content. Confirmation binds to this immutable body id."},
                "message": {"type": "string"},
                "sha": {"type": "string", "description": "The `sha` docs.get returned for this path."},
                "confirm": {"type": "string"},
            },
            "required": ["path", "message", "sha"],
            "oneOf": [{"required": ["content"]}, {"required": ["contentStaged"]}],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="docs.review_comment",
        family=DOCS,
        access=REVIEW,
        role=DOCS_REVIEWER,
        requires=_REVIEW_HOST,
        description=(
            "Add an advisory comment to a proposal (two-step, like the others). It is a comment "
            "and nothing else: it cannot approve, cannot request changes, and cannot satisfy a "
            "required-approvals rule. It is posted under your own identity and carries a footer "
            "saying it came through this gateway."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "change": _CHANGE,
                "body": {"type": "string"},
                "confirm": {"type": "string"},
            },
            "required": ["change", "body"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="docs.review_get",
        family=DOCS,
        requires=_REVIEW_HOST,
        description="One proposal's state, title and url (read-only).",
        input_schema={
            "type": "object",
            "properties": {"change": {"type": "integer", "minimum": 1}},
            "required": ["change"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="docs.review_list",
        family=DOCS,
        requires=_REVIEW_HOST,
        description="List open proposals in this project's corpus repository, most recently updated first (read-only, no confirmation). Rows include number, title, author, updated, url and isAuthor for your enrolled host identity.",
        input_schema={
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20}},
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="docs.review_add_reviewer",
        family=DOCS,
        access=REVIEW,
        role=DOCS_REVIEWER,
        requires=_REVIEW_HOST,
        description="Request review from a named account on an open proposal in this project's corpus repository. Idempotent and audit-logged; needs docs_reviewer. Requires two-step confirmation because it changes requested reviewers on the host.",
        input_schema={
            "type": "object",
            "properties": {"change": {"type": "integer", "minimum": 1}, "reviewer": {"type": "string"}, "confirm": {"type": "string"}},
            "required": ["change", "reviewer"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="docs.review_abandon",
        family=DOCS,
        access=WRITE,
        role=DOCS_WRITER,
        requires=_REVIEW_HOST,
        description="Withdraw your OWN open proposal in this project's corpus repository. Author-only on the review host; anyone else's proposal is human-only. Needs docs_writer and two-step confirmation; optional message is stamped. Closes the proposal without deleting its branch.",
        input_schema={
            "type": "object",
            "properties": {"change": {"type": "integer", "minimum": 1}, "message": {"type": "string"}, "confirm": {"type": "string"}},
            "required": ["change"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="docs.asset_stage_url",
        family=DOCS,
        access=WRITE,
        role=DOCS_WRITER,
        requires=_STAGE,
        description="Stage one UTF-8 Markdown body (content only). Returns a doc_ stagedId and a single-use upload URL valid for 60 seconds. PUT the bytes to that URL with your gateway bearer token, then pass contentStaged to docs.create/update in both confirmation steps. Maximum 2 MiB; uploaded bodies expire after one hour and remain reusable after a failed proposal. Needs docs_writer; staging itself requires no confirmation.",
        input_schema={
            "type": "object",
            "properties": {"kind": {"type": "string", "enum": ["content"], "default": "content"}},
            "additionalProperties": False,
        },
    ),
)


def call(host: ToolHost, name: str, arguments: dict[str, Any], principal: Principal, context: RequestContext) -> dict[str, Any]:
    corpus = host.docs_corpus
    if corpus is None:
        raise DocsBackendError("docs corpus is not enabled on this gateway", status=404)
    # Reads share the per-user read budget with memory reads.
    host.enforce_read_quota(principal)
    if name == "docs.search":
        query = args.required_text(arguments, "query", max_len=512)
        return corpus.search(query, args.limit(arguments.get("limit"), 8), context)
    if name == "docs.get":
        path = args.required_text(arguments, "path", max_len=500)
        return corpus.get(path, context)
    if name == "docs.list":
        return corpus.list(context)
    if name == "docs.lint":
        return corpus.lint(context)
    review = host.docs_review
    if review is None:
        raise DocsBackendError(
            "this project's docs corpus is read-only: no review host is configured for it",
            status=404,
        )
    if name == "docs.review_get":
        return review.get(args.required_change_ref(arguments), context)
    if name == "docs.review_list":
        limit = args.optional_int(arguments, "limit", minimum=1, maximum=50)
        return review.list(limit if limit is not None else 20, context)
    if name == "docs.review_add_reviewer":
        reviewer = args.required_text(arguments, "reviewer", max_len=39)
        change_ref = args.required_change_ref(arguments)
        pending = host.confirmation_gate(
            name, {"change": change_ref, "reviewer": reviewer}, arguments, principal,
            f"Request review from {reviewer!r} on proposal #{change_ref}")
        if pending is not None:
            return pending
        return review.add_reviewer(change_ref, reviewer, context)
    if name == "docs.review_abandon":
        change_ref = args.required_change_ref(arguments)
        message = args.optional_text(arguments, "message", max_len=20_000)
        reject_secret(find_secret(message or ""))
        semantic: dict[str, Any] = {"change": change_ref}
        if message is not None:
            semantic["message"] = message
        pending = host.confirmation_gate(
            name, semantic, arguments, principal, f"Withdraw your proposal #{change_ref}")
        if pending is not None:
            return pending
        return review.abandon(change_ref, message, context)
    stage = host.asset_stage
    if name == "docs.asset_stage_url":
        if not review.has_project(context.project) or stage is None:
            raise DocsBackendError("staged content is not configured for this project", status=404)
        kind = args.required_text(arguments, "kind", max_len=16) if "kind" in arguments else "content"
        return stage.mint_upload_url(context.actor, context.project, principal.token_id, kind)
    if name in ("docs.create", "docs.update"):
        path = args.required_text(arguments, "path", max_len=500)
        if "contentStaged" in arguments and "content" in arguments:
            raise ValueError("pass content OR contentStaged, not both")
        staged_id = None
        if "contentStaged" in arguments:
            staged_id = args.required_text(arguments, "contentStaged", max_len=64)
            if not staged_id.startswith("doc_"):
                raise ValueError("contentStaged must be a doc_ id from docs.asset_stage_url(kind='content')")
            if stage is None:
                raise DocsBackendError("staged content is not configured on this gateway", status=404)
            content = stage.peek(staged_id, context.actor, context.project, principal.token_id)
        else:
            content = args.required_text(arguments, "content", max_len=200_000)
        message = args.required_text(arguments, "message", max_len=255)
        # Everything that gets committed, not just the prose: a document body
        # is the most likely place in this whole gateway for a pasted
        # credential to end up, and a corpus is team-visible.
        reject_secret(find_secret(path, content, message))
        # A stage is immutable: its id binds the body without asking the
        # caller to resend it. Inline bodies must bind their full text.
        semantic = {"path": path, "message": message,
                    **({"contentStaged": staged_id} if staged_id is not None else {"content": content})}
        base_sha = None
        if name == "docs.update":
            base_sha = args.required_text(arguments, "sha", max_len=64)
            semantic["sha"] = base_sha
        pending = host.confirmation_gate(
            name, semantic, arguments, principal, f"Propose a document change to {path!r}")
        if pending is not None:
            return pending

        def propose(body: str) -> dict[str, Any]:
            if name == "docs.create":
                return review.create(path, body, message, context)
            assert base_sha is not None   # required above for docs.update
            return review.update(path, body, message, base_sha, context)

        if staged_id is not None:
            assert stage is not None
            # Claim across the host call so concurrent confirmations cannot
            # both consume one body; a failed proposal releases it for retry.
            with stage.claim(staged_id, context.actor, context.project, principal.token_id) as body:
                return propose(body)
        return propose(content)
    if name == "docs.review_comment":
        change_ref = args.required_change_ref(arguments)
        body = args.required_text(arguments, "body", max_len=20_000)
        reject_secret(find_secret(body))
        pending = host.confirmation_gate(
            name, {"change": change_ref, "body": body}, arguments, principal,
            f"Comment on proposal #{change_ref}")
        if pending is not None:
            return pending
        return review.comment(change_ref, body, context)
    raise ValueError(f"Unknown docs tool: {name}")
