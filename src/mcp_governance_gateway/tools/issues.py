"""The issue-tracker family: Redmine or GitLab, one per deployment (ADR-0013).

Tenancy is the token's `issue_project`; reads need only that, writes need the
issue_writer role and go through the two-step confirmation (ADR-0003).
"""
from __future__ import annotations

from typing import Any

from ..auth import Principal
from ..issue_backend import IssueBackendError
from ..memory_backend import RequestContext
from ..secret_scan import find_secret
from . import args
from .base import FEATURE_ISSUES, ISSUE_WRITER, ISSUES, WRITE, ToolHost, ToolSpec
from .memory import reject_secret

_ISSUE_REF = {"type": ["string", "integer"]}
_LIMIT = {"type": "integer", "minimum": 1, "maximum": 50, "default": 20}
_ASSIGNEE = {
    "type": "string",
    "description": "Optional numeric user id (GitLab also accepts a username).",
}
_PARENT = {
    "type": ["string", "integer"],
    "description": "Optional parent issue id — must be in this project. Redmine only.",
}


def _read(name: str, description: str, properties: dict[str, Any], required: list[str] | None = None) -> ToolSpec:
    schema: dict[str, Any] = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        schema["required"] = required
    return ToolSpec(name=name, description=description, input_schema=schema, family=ISSUES,
                    requires=frozenset({FEATURE_ISSUES}))


def _write(name: str, description: str, properties: dict[str, Any], required: list[str]) -> ToolSpec:
    schema: dict[str, Any] = {
        "type": "object",
        "properties": {**properties, "confirm": {"type": "string"}},
        "required": required,
        "additionalProperties": False,
    }
    return ToolSpec(name=name, description=description, input_schema=schema, family=ISSUES,
                    access=WRITE, role=ISSUE_WRITER, requires=frozenset({FEATURE_ISSUES}))


TOOLS: tuple[ToolSpec, ...] = (
    _read("issues.get", "Get one issue by id (scoped to your project).", {"id": _ISSUE_REF}, ["id"]),
    _read(
        "issues.search",
        "Search this project's issues by status/assignee.",
        {
            "status": {
                "type": "string",
                "description": (
                    "A status name this tracker defines (normalized, e.g. \"IN_PROGRESS\"), or "
                    "\"open\" / \"closed\" / \"*\"."
                ),
            },
            "assignee": {
                "type": "string",
                "description": (
                    "Numeric user id as a string (e.g. \"42\"), or \"me\" — a name or email "
                    "silently matches nothing rather than erroring."
                ),
            },
            "limit": _LIMIT,
        },
    ),
    _read(
        "issues.mine",
        (
            "Issues in this project assigned to you. Identity comes from your own enrolled tracker "
            "credential — the shared service credential cannot stand in for you, so this fails with "
            "setup instructions rather than returning someone else's issues."
        ),
        {"limit": _LIMIT},
    ),
    _read(
        "issues.categories",
        (
            "This project's issue categories (id + name), fetched live. Call this for the valid values of "
            "the `category` argument on issues.create / issues.update_status — categories are per-project "
            "and change over time, so there is no fixed list to guess from. Redmine only: GitLab has no "
            "category concept (it uses labels) and says so."
        ),
        {},
    ),
    _write(
        "issues.create",
        (
            "Create an issue in your project. Non-destructive write: the first call returns a "
            "confirmationId; re-call with the same arguments plus \"confirm\" to commit."
        ),
        {
            "subject": {"type": "string", "minLength": 1},
            "description": {"type": "string"},
            "tracker": {
                "type": "string",
                "description": (
                    "Optional tracker name this instance defines (a stock Redmine has Bug / Feature / "
                    "Support); the project's default tracker applies when omitted. An unknown name is "
                    "rejected with the list this instance offers. Redmine only; ignored on GitLab."
                ),
            },
            "assignee": _ASSIGNEE,
            "startDate": {"type": "string", "description": "Optional YYYY-MM-DD. Redmine only."},
            "dueDate": {"type": "string", "description": "Optional YYYY-MM-DD. Redmine only."},
            "priority": {
                "type": "string",
                "description": (
                    "Optional priority name this tracker defines (a stock Redmine has low / normal / "
                    "high / urgent / immediate); the project's own default applies when omitted. "
                    "An unknown name is rejected with the list this instance offers. Redmine only."
                ),
            },
            "parentIssue": _PARENT,
            "category": {
                "type": "string",
                "description": (
                    "Optional category name from this project — call issues.categories for the valid "
                    "values, they are per-project and not a fixed set. Redmine only."
                ),
            },
        },
        ["subject"],
    ),
    _write(
        "issues.add_note",
        "Add a note to an issue in your project. Non-destructive write: requires confirm (see issues.create).",
        {"id": _ISSUE_REF, "note": {"type": "string", "minLength": 1}},
        ["id", "note"],
    ),
    _write(
        "issues.update_status",
        "Update an issue's status (and optional doneRatio) in your project. Non-destructive write: requires confirm.",
        {
            "id": _ISSUE_REF,
            "status": {
                "type": "string",
                "description": (
                    "A status name this tracker defines (normalized, e.g. \"IN_PROGRESS\"). An "
                    "unknown name is rejected with the list this instance offers."
                ),
            },
            "doneRatio": {"type": "integer", "minimum": 0, "maximum": 100, "description": "Redmine only."},
            "assignee": _ASSIGNEE,
            "startDate": {"type": "string", "description": "Optional YYYY-MM-DD. Redmine only."},
            "dueDate": {"type": "string", "description": "Optional YYYY-MM-DD. Redmine only."},
            "priority": {
                "type": "string",
                "description": (
                    "Optional priority name this tracker defines; an unknown name is rejected with "
                    "the list this instance offers. Redmine only."
                ),
            },
            "parentIssue": _PARENT,
            "category": {
                "type": "string",
                "description": (
                    "Optional category name from this project — call issues.categories for the valid "
                    "values. Redmine only."
                ),
            },
        },
        ["id", "status"],
    ),
)


def call(host: ToolHost, name: str, arguments: dict[str, Any], principal: Principal, context: RequestContext) -> dict[str, Any]:
    backend = host.issue_backend
    if backend is None:
        raise IssueBackendError("issue tracker adapter is not configured")
    if name == "issues.get":
        issue_id = args.required_issue_ref(arguments, "id")
        return backend.get(issue_id, context)
    if name == "issues.search":
        limit = args.limit(arguments.get("limit"), default=20)
        filters: dict[str, Any] = {}
        if arguments.get("status") is not None:
            filters["status"] = args.required_text(arguments, "status", max_len=40)
        if arguments.get("assignee") is not None:
            filters["assignee"] = args.required_text(arguments, "assignee", max_len=40)
        return backend.search(filters, limit, context)
    if name == "issues.mine":
        limit = args.limit(arguments.get("limit"), default=20)
        return backend.mine(limit, context)
    if name == "issues.categories":
        return backend.categories(context)
    if name == "issues.create":
        subject = args.required_text(arguments, "subject", max_len=255)
        description = args.optional_text(arguments, "description", max_len=10000)
        tracker = args.optional_text(arguments, "tracker", max_len=60)
        assignee = args.optional_text(arguments, "assignee", max_len=40)
        planning = args.planning_fields(arguments)
        # Every field that gets persisted, not just the prose ones: `priority`
        # and `assignee` are short, but "short" is not "cannot hold a
        # credential" -- an AWS key id is exactly 20 characters.
        reject_secret(find_secret(subject, description, tracker, assignee, *args.planning_texts(planning)))
        semantic: dict[str, Any] = {"subject": subject}
        if description is not None:
            semantic["description"] = description
        if tracker is not None:
            semantic["tracker"] = tracker
        if assignee is not None:
            semantic["assignee"] = assignee
        semantic.update(planning)
        pending = host.confirmation_gate(name, semantic, arguments, principal, f"Create issue: {subject!r}")
        if pending is not None:
            return pending
        fields: dict[str, Any] = {"subject": subject, "description": description}
        if tracker is not None:
            fields["tracker"] = tracker
        if assignee is not None:
            fields["assignee"] = assignee
        fields.update(planning)
        return backend.create(fields, context)
    if name == "issues.add_note":
        issue_id = args.required_issue_ref(arguments, "id")
        note = args.required_text(arguments, "note", max_len=10000)
        reject_secret(find_secret(note))
        semantic = {"id": issue_id, "note": note}
        pending = host.confirmation_gate(name, semantic, arguments, principal, f"Add note to issue #{issue_id}")
        if pending is not None:
            return pending
        return backend.add_note(issue_id, note, context)
    if name == "issues.update_status":
        issue_id = args.required_issue_ref(arguments, "id")
        status = args.required_text(arguments, "status", max_len=40)
        done_ratio = args.optional_int(arguments, "doneRatio", minimum=0, maximum=100)
        assignee = args.optional_text(arguments, "assignee", max_len=40)
        planning = args.planning_fields(arguments)
        reject_secret(find_secret(assignee, *args.planning_texts(planning)))
        semantic = {"id": issue_id, "status": status}
        if done_ratio is not None:
            semantic["doneRatio"] = done_ratio
        if assignee is not None:
            semantic["assignee"] = assignee
        semantic.update(planning)
        pending = host.confirmation_gate(
            name, semantic, arguments, principal, f"Set issue #{issue_id} status to {status}"
        )
        if pending is not None:
            return pending
        return backend.update_status(issue_id, status, done_ratio, context, assignee=assignee, planning=planning)
    raise ValueError(f"unsupported tool: {name}")
