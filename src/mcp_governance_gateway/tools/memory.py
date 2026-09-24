"""The memory family: this project's memories, lessons and follow-up actions.

Tenancy is the token's project, injected by the backend adapter. Writes are not
confirmation-gated (ADR-0003 reserves that for systems of record) but are
secret-scanned and rate-limited; reads share the per-user read budget.
"""
from __future__ import annotations

from typing import Any

from ..auth import Principal
from ..memory_backend import RequestContext
from ..secret_scan import find_secret
from . import args
from .base import MEMORY, READ, WRITE, ToolHost, ToolSpec


def reject_secret(label: str | None) -> None:
    if label:
        raise ValueError(
            f"possible secret detected ({label}) — redact it and retry: "
            "memory and issue writes are team-visible and append-only (no delete)"
        )


_LIMIT = {"type": "integer", "minimum": 1, "maximum": 50, "default": 20}

TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="memory.search",
        family=MEMORY,
        description=(
            "Search this project's memories — the recall path. Keyword matching, so identifiers, "
            "error codes and jargon work well; use memory.list only when you want the whole corpus."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "minLength": 1},
                "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="memory.save",
        family=MEMORY,
        access=WRITE,
        description=(
            "Save ONE atomic durable fact in 1-3 sentences — a decision and why, a root cause and "
            "fix, or a constraint not visible in the code. NOT a progress/session report, NOT an "
            "action's status (the board has it), NOT what git already records; long supporting "
            "evidence belongs in a document, and memory keeps the conclusion. Append-only and "
            "team-visible (actor recorded for audit)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "text": {"type": "string", "minLength": 1},
                "tags": {"type": "array", "items": {"type": "string"}, "maxItems": 20},
            },
            "required": ["text"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="memory.list",
        family=MEMORY,
        description=(
            "List this project's memories, newest first, paginated (each item carries its actor tag). "
            "Audit/report use — wrap-ups, \"who wrote what\". For recall use memory.search instead: it "
            "returns what is relevant rather than the whole corpus."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "limit": _LIMIT,
                "offset": {"type": "integer", "minimum": 0},
            },
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="memory.lesson_save",
        family=MEMORY,
        access=WRITE,
        description=(
            "Save a project-scoped 'never do this again' rule; persists across sessions. Use when the "
            "user corrects a mistake worth not repeating."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "rule": {"type": "string", "minLength": 1, "description": "Imperative rule, e.g. 'Always run lint before committing'."},
                "reason": {"type": "string", "description": "Why it matters (optional)."},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1, "description": "0-1 (default 0.8)."},
            },
            "required": ["rule"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="memory.lesson_list",
        family=MEMORY,
        description="List this project's lessons (confidence-scored rules), highest confidence first.",
        input_schema={
            "type": "object",
            "properties": {"limit": _LIMIT},
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="memory.action_create",
        family=MEMORY,
        access=WRITE,
        description=(
            "Create a project-scoped follow-up (status starts 'pending'; persists across sessions). "
            "Lighter than an issue — use issues.* for formal tickets."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "title": {"type": "string", "minLength": 1},
                "description": {"type": "string"},
                "priority": {"type": "string", "description": "e.g. low / medium / high (optional)."},
            },
            "required": ["title"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="memory.action_list",
        family=MEMORY,
        description=(
            "List this project's OPEN actions (pending/active/blocked) — the live follow-up board. "
            "includeDone:true adds completed ones (for reports)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "limit": _LIMIT,
                "includeDone": {"type": "boolean", "default": False},
            },
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="memory.action_update_status",
        family=MEMORY,
        access=WRITE,
        description=(
            "Advance an action pending -> active -> done/blocked, so action_list stays a live board. "
            "Scoped to your project (an action id from another project is rejected)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "action_id": {"type": "string", "minLength": 1},
                "status": {"type": "string", "enum": ["active", "done", "blocked"]},
            },
            "required": ["action_id", "status"],
            "additionalProperties": False,
        },
    ),
)

assert all(t.access in (READ, WRITE) for t in TOOLS)


def _take_write_quota(host: ToolHost, principal: Principal, text: str) -> None:
    quota = host.write_limiter.check_and_record(principal, text)
    if not quota.allowed:
        raise PermissionError(quota.reason)


def call(host: ToolHost, name: str, arguments: dict[str, Any], principal: Principal, context: RequestContext) -> dict[str, Any]:
    backend = host.memory_backend
    if name == "memory.search":
        query = args.required_text(arguments, "query", max_len=1000)
        limit = args.limit(arguments.get("limit"), default=10)
        host.enforce_read_quota(principal)
        return backend.search(query, limit, context)
    if name == "memory.save":
        text = args.required_text(arguments, "text", max_len=10000)
        tags = args.tags(arguments.get("tags", []))
        reject_secret(find_secret(text, *tags))
        _take_write_quota(host, principal, text)
        return backend.save(text, tags, context)
    if name == "memory.list":
        limit = args.limit(arguments.get("limit"), default=20)
        offset = args.offset(arguments.get("offset"))
        host.enforce_read_quota(principal)
        return backend.list(limit, offset, context)
    if name == "memory.lesson_save":
        rule = args.required_text(arguments, "rule", max_len=2000)
        reason = args.optional_text(arguments, "reason", max_len=4000)
        confidence = args.confidence(arguments.get("confidence"))
        reject_secret(find_secret(rule, reason))
        _take_write_quota(host, principal, rule)
        return backend.lesson_save(rule, reason, confidence, context)
    if name == "memory.lesson_list":
        limit = args.limit(arguments.get("limit"), default=20)
        host.enforce_read_quota(principal)
        return backend.lesson_list(limit, context)
    if name == "memory.action_create":
        title = args.required_text(arguments, "title", max_len=500)
        description = args.optional_text(arguments, "description", max_len=4000)
        priority = args.optional_text(arguments, "priority", max_len=20)
        reject_secret(find_secret(title, description, priority))
        _take_write_quota(host, principal, title)
        return backend.action_create(title, description, priority, context)
    if name == "memory.action_list":
        limit = args.limit(arguments.get("limit"), default=20)
        include_done = arguments.get("includeDone", False)
        if not isinstance(include_done, bool):
            raise ValueError("includeDone must be a boolean")
        host.enforce_read_quota(principal)
        return backend.action_list(limit, context, include_done=include_done)
    if name == "memory.action_update_status":
        action_id = args.required_text(arguments, "action_id", max_len=200)
        status = args.required_text(arguments, "status", max_len=20)
        if status not in ("active", "done", "blocked"):
            raise ValueError("status must be one of: active, done, blocked")
        _take_write_quota(host, principal, action_id)
        return backend.action_update_status(action_id, status, context)
    raise ValueError(f"unsupported tool: {name}")
