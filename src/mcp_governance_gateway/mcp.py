from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import time
import uuid
from typing import Any

from . import __version__
from .audit import AuditEvent, AuditSink
from .auth import Principal
from .confirm import ConfirmationStore
from .ci_backend import JenkinsHttpBackend
from .docs_backend import DocsBackendError, DocsCorpus
from .issue_backend import IssueBackend, IssueBackendError
from .limits import InMemoryMemoryWriteLimiter, MemoryLimitConfig, MemoryWriteLimiter
from .memory_backend import MemoryBackend, MemoryBackendError, RequestContext
from .secret_scan import find_secret

PROTOCOL_VERSION = "2025-06-18"


def _reject_secret(label: str | None) -> None:
    if label:
        raise ValueError(
            f"possible secret detected ({label}) — redact it and retry: "
            "memory and issue writes are team-visible and append-only (no delete)"
        )

_ISSUE_READ_TOOLS = frozenset({"issues.get", "issues.search", "issues.mine", "issues.categories"})
_ISSUE_WRITE_TOOLS = frozenset({"issues.create", "issues.add_note", "issues.update_status"})
_ISSUE_TOOLS = _ISSUE_READ_TOOLS | _ISSUE_WRITE_TOOLS
# Issue writes need an explicit role (default-deny); reads need only an issue_project.
_ISSUE_WRITE_ROLE = "issue_writer"
# Docs tools are read-only over the project's reviewed docs repo; tenancy is the
# token's project claim (the corpus map is keyed by project — no new role needed).
_DOCS_TOOLS = frozenset({"docs.search", "docs.get", "docs.list"})
# CI tools are read-only; tenancy is the server-side project->jobs allowlist.
_CI_TOOLS = frozenset({"ci.status", "ci.log", "ci.artifact"})


@dataclass(frozen=True)
class PolicyDecision:
    decision: str
    reason: str

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


class Policy:
    # Phase 1 authorization is a project-scoped, exact-match allow-list. The token's
    # `roles` are carried on the Principal but are NOT used here yet: role-based RBAC
    # and role-dependent tool visibility are deferred. Memory tools are allowed for
    # any token that carries a project; issue tools additionally require the token to
    # carry an issue_project (the tenant boundary for the issue tracker). Everything
    # else is denied, and destructive operations are always denied. See roadmap Phase 5.
    _ALLOWED_MEMORY_TOOLS = frozenset({"memory.search", "memory.save", "memory.list", "memory.lesson_save", "memory.lesson_list", "memory.action_create", "memory.action_list", "memory.action_update_status"})
    _DESTRUCTIVE_SUFFIXES = ("delete", "destroy", "purge", "remove")

    def decide(self, tool_name: str, principal: Principal) -> PolicyDecision:
        if not principal.project:
            return PolicyDecision("deny", "missing project")
        if tool_name.split(".")[-1] in self._DESTRUCTIVE_SUFFIXES:
            return PolicyDecision("deny", "destructive operations are denied")
        if tool_name in self._ALLOWED_MEMORY_TOOLS:
            return PolicyDecision("allow", "phase1 memory tool")
        if tool_name in _DOCS_TOOLS:
            return PolicyDecision("allow", "docs read")
        if tool_name in _CI_TOOLS:
            return PolicyDecision("allow", "ci read")
        if tool_name in _ISSUE_TOOLS:
            if not principal.issue_project:
                return PolicyDecision("deny", "token has no issue project")
            if tool_name in _ISSUE_WRITE_TOOLS:
                if _ISSUE_WRITE_ROLE not in principal.roles:
                    return PolicyDecision("deny", "token lacks issue write role")
                return PolicyDecision("allow", "phase1 issue write")
            return PolicyDecision("allow", "phase1 issue read")
        return PolicyDecision("deny", "tool is not allowed in phase1")


class GatewayApp:
    def __init__(
        self,
        memory_backend: MemoryBackend,
        audit_sink: AuditSink,
        policy: Policy | None = None,
        memory_write_limiter: MemoryWriteLimiter | None = None,
        issue_backend: IssueBackend | None = None,
        confirmation: ConfirmationStore | None = None,
        docs_corpus: DocsCorpus | None = None,
        ci_backend: JenkinsHttpBackend | None = None,
    ) -> None:
        self._memory_backend = memory_backend
        self._audit_sink = audit_sink
        self._policy = policy or Policy()
        self._memory_write_limiter = memory_write_limiter or InMemoryMemoryWriteLimiter(MemoryLimitConfig())
        self._issue_backend = issue_backend
        self._confirm = confirmation or ConfirmationStore()
        self._docs_corpus = docs_corpus
        self._ci_backend = ci_backend

    def handle_rpc(self, message: dict[str, Any], principal: Principal) -> dict[str, Any] | None:
        if message.get("jsonrpc") != "2.0":
            return _error(message.get("id"), -32600, "Invalid Request")

        request_id = message.get("id")
        method = message.get("method")
        params = message.get("params") or {}
        if not isinstance(method, str):
            return _error(request_id, -32600, "Invalid Request")
        if not isinstance(params, dict):
            return _error(request_id, -32602, "Invalid params")

        if request_id is None and method == "notifications/initialized":
            return None
        if request_id is None:
            return None

        if method == "initialize":
            return _result(request_id, self._initialize(params))
        if method == "ping":
            return _result(request_id, {})
        if method == "tools/list":
            docs_enabled = self._docs_corpus is not None and self._docs_corpus.has_project(principal.project)
            ci_enabled = self._ci_backend is not None and self._ci_backend.has_project(principal.project)
            tools = visible_tool_definitions(principal, self._issue_backend is not None, docs_enabled, ci_enabled)
            return _result(request_id, {"tools": tools})
        if method == "tools/call":
            return self._handle_tool_call(request_id, params, principal)
        return _error(request_id, -32601, f"Method not found: {method}")

    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {
                "name": "mcp-governance-gateway",
                "title": "MCP Governance Gateway",
                "version": __version__,
            },
        }

    def _handle_tool_call(self, request_id: Any, params: dict[str, Any], principal: Principal) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return _error(request_id, -32602, "Invalid tool call params")

        gateway_request_id = str(uuid.uuid4())
        start = time.monotonic()
        decision = self._policy.decide(name, principal)
        if not decision.allowed:
            self._audit(name, principal, gateway_request_id, decision, "denied", start=start)
            return _error(request_id, -32003, decision.reason)
        if name not in {tool["name"] for tool in tool_definitions()}:
            unknown = PolicyDecision("deny", "unknown tool")
            self._audit(name, principal, gateway_request_id, unknown, "denied", start=start)
            return _error(request_id, -32602, f"Unknown tool: {name}")

        context = RequestContext.from_principal(principal, gateway_request_id)
        try:
            if name in _ISSUE_TOOLS:
                result = self._call_issue_tool(name, arguments, principal, context)
            elif name in _DOCS_TOOLS:
                result = self._call_docs_tool(name, arguments, principal, context)
            elif name in _CI_TOOLS:
                result = self._call_ci_tool(name, arguments, principal, context)
            else:
                result = self._call_memory_tool(name, arguments, principal, context)
        except ValueError as exc:
            self._audit(name, principal, gateway_request_id, decision, "invalid", start=start)
            return _error(request_id, -32602, str(exc))
        except PermissionError as exc:
            denied = PolicyDecision("deny", str(exc))
            self._audit(name, principal, gateway_request_id, denied, "denied", start=start)
            return _error(request_id, -32003, str(exc))
        except (MemoryBackendError, IssueBackendError, DocsBackendError) as exc:
            backend_status = str(exc.status) if exc.status is not None else "error"
            self._audit(
                name, principal, gateway_request_id, decision, "backend_error",
                start=start, backend_status=backend_status,
            )
            return _result(request_id, _tool_error(str(exc)))

        if isinstance(result, dict) and result.get("confirmationRequired"):
            self._audit(name, principal, gateway_request_id, decision, "confirm_required", start=start)
            return _result(request_id, _tool_result(result))

        resource_id = result.get("id") if isinstance(result, dict) else None
        self._audit(
            name, principal, gateway_request_id, decision, "ok",
            start=start, backend_status="ok", resource_id=resource_id,
        )
        return _result(request_id, _tool_result(result))

    def _call_memory_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        principal: Principal,
        context: RequestContext,
    ) -> dict[str, Any]:
        if name == "memory.search":
            query = _required_text(arguments, "query", max_len=1000)
            limit = _limit(arguments.get("limit"), default=10)
            self._enforce_read_quota(principal)
            return self._memory_backend.search(query, limit, context)
        if name == "memory.save":
            text = _required_text(arguments, "text", max_len=10000)
            tags = _tags(arguments.get("tags", []))
            _reject_secret(find_secret(text, *tags))
            quota = self._memory_write_limiter.check_and_record(principal, text)
            if not quota.allowed:
                raise PermissionError(quota.reason)
            return self._memory_backend.save(text, tags, context)
        if name == "memory.list":
            limit = _limit(arguments.get("limit"), default=20)
            offset = _offset(arguments.get("offset"))
            self._enforce_read_quota(principal)
            return self._memory_backend.list(limit, offset, context)
        if name == "memory.lesson_save":
            rule = _required_text(arguments, "rule", max_len=2000)
            reason = _optional_text(arguments, "reason", max_len=4000)
            confidence = _confidence(arguments.get("confidence"))
            _reject_secret(find_secret(rule, reason))
            quota = self._memory_write_limiter.check_and_record(principal, rule)
            if not quota.allowed:
                raise PermissionError(quota.reason)
            return self._memory_backend.lesson_save(rule, reason, confidence, context)
        if name == "memory.lesson_list":
            limit = _limit(arguments.get("limit"), default=20)
            self._enforce_read_quota(principal)
            return self._memory_backend.lesson_list(limit, context)
        if name == "memory.action_create":
            title = _required_text(arguments, "title", max_len=500)
            description = _optional_text(arguments, "description", max_len=4000)
            priority = _optional_text(arguments, "priority", max_len=20)
            _reject_secret(find_secret(title, description, priority))
            quota = self._memory_write_limiter.check_and_record(principal, title)
            if not quota.allowed:
                raise PermissionError(quota.reason)
            return self._memory_backend.action_create(title, description, priority, context)
        if name == "memory.action_list":
            limit = _limit(arguments.get("limit"), default=20)
            include_done = arguments.get("includeDone", False)
            if not isinstance(include_done, bool):
                raise ValueError("includeDone must be a boolean")
            self._enforce_read_quota(principal)
            return self._memory_backend.action_list(limit, context, include_done=include_done)
        if name == "memory.action_update_status":
            action_id = _required_text(arguments, "action_id", max_len=200)
            status = _required_text(arguments, "status", max_len=20)
            if status not in ("active", "done", "blocked"):
                raise ValueError("status must be one of: active, done, blocked")
            quota = self._memory_write_limiter.check_and_record(principal, action_id)
            if not quota.allowed:
                raise PermissionError(quota.reason)
            return self._memory_backend.action_update_status(action_id, status, context)
        raise ValueError(f"unsupported tool: {name}")

    def _call_issue_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        principal: Principal,
        context: RequestContext,
    ) -> dict[str, Any]:
        if self._issue_backend is None:
            raise IssueBackendError("issue tracker adapter is not configured")
        if name == "issues.get":
            issue_id = _required_issue_ref(arguments, "id")
            return self._issue_backend.get(issue_id, context)
        if name == "issues.search":
            limit = _limit(arguments.get("limit"), default=20)
            filters: dict[str, Any] = {}
            if arguments.get("status") is not None:
                filters["status"] = _required_text(arguments, "status", max_len=40)
            if arguments.get("assignee") is not None:
                filters["assignee"] = _required_text(arguments, "assignee", max_len=40)
            return self._issue_backend.search(filters, limit, context)
        if name == "issues.mine":
            limit = _limit(arguments.get("limit"), default=20)
            return self._issue_backend.mine(limit, context)
        if name == "issues.categories":
            return self._issue_backend.categories(context)
        if name == "issues.create":
            subject = _required_text(arguments, "subject", max_len=255)
            description = _optional_text(arguments, "description", max_len=10000)
            tracker = _optional_text(arguments, "tracker", max_len=60)
            assignee = _optional_text(arguments, "assignee", max_len=40)
            planning = _planning_fields(arguments)
            # Every field that gets persisted, not just the prose ones: `priority`
            # and `assignee` are short, but "short" is not "cannot hold a
            # credential" -- an AWS key id is exactly 20 characters.
            _reject_secret(find_secret(subject, description, tracker, assignee, *_planning_texts(planning)))
            semantic: dict[str, Any] = {"subject": subject}
            if description is not None:
                semantic["description"] = description
            if tracker is not None:
                semantic["tracker"] = tracker
            if assignee is not None:
                semantic["assignee"] = assignee
            semantic.update(planning)
            pending = self._confirmation_gate(name, semantic, arguments, principal, f"Create issue: {subject!r}")
            if pending is not None:
                return pending
            fields: dict[str, Any] = {"subject": subject, "description": description}
            if tracker is not None:
                fields["tracker"] = tracker
            if assignee is not None:
                fields["assignee"] = assignee
            fields.update(planning)
            return self._issue_backend.create(fields, context)
        if name == "issues.add_note":
            issue_id = _required_issue_ref(arguments, "id")
            note = _required_text(arguments, "note", max_len=10000)
            _reject_secret(find_secret(note))
            semantic = {"id": issue_id, "note": note}
            pending = self._confirmation_gate(name, semantic, arguments, principal, f"Add note to issue #{issue_id}")
            if pending is not None:
                return pending
            return self._issue_backend.add_note(issue_id, note, context)
        if name == "issues.update_status":
            issue_id = _required_issue_ref(arguments, "id")
            status = _required_text(arguments, "status", max_len=40)
            done_ratio = _optional_int(arguments, "doneRatio", minimum=0, maximum=100)
            assignee = _optional_text(arguments, "assignee", max_len=40)
            planning = _planning_fields(arguments)
            _reject_secret(find_secret(assignee, *_planning_texts(planning)))
            semantic: dict[str, Any] = {"id": issue_id, "status": status}
            if done_ratio is not None:
                semantic["doneRatio"] = done_ratio
            if assignee is not None:
                semantic["assignee"] = assignee
            semantic.update(planning)
            pending = self._confirmation_gate(
                name, semantic, arguments, principal, f"Set issue #{issue_id} status to {status}"
            )
            if pending is not None:
                return pending
            return self._issue_backend.update_status(
                issue_id, status, done_ratio, context, assignee=assignee, planning=planning
            )
        raise ValueError(f"unsupported tool: {name}")

    def _call_docs_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        principal: Principal,
        context: RequestContext,
    ) -> dict[str, Any]:
        if self._docs_corpus is None:
            raise DocsBackendError("docs corpus is not enabled on this gateway", status=404)
        # Reads share the per-user read budget with memory reads.
        self._enforce_read_quota(principal)
        if name == "docs.search":
            query = _required_text(arguments, "query", max_len=512)
            return self._docs_corpus.search(query, _limit(arguments.get("limit"), 8), context)
        if name == "docs.get":
            path = _required_text(arguments, "path", max_len=500)
            return self._docs_corpus.get(path, context)
        if name == "docs.list":
            return self._docs_corpus.list(context)
        raise ValueError(f"Unknown docs tool: {name}")

    def _call_ci_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        principal: Principal,
        context: RequestContext,
    ) -> dict[str, Any]:
        if self._ci_backend is None:
            raise DocsBackendError("CI is not enabled on this gateway", status=404)
        self._enforce_read_quota(principal)
        if name == "ci.status":
            return self._ci_backend.status(context)
        if name == "ci.log":
            job = _required_text(arguments, "job", max_len=200)
            return self._ci_backend.log(job, context, _optional_int(arguments, "lines", minimum=1, maximum=1000))
        if name == "ci.artifact":
            job = _required_text(arguments, "job", max_len=200)
            build = _optional_int(arguments, "build", minimum=1, maximum=1_000_000_000)
            return self._ci_backend.artifacts(job, context, build)
        raise ValueError(f"Unknown ci tool: {name}")

    def _confirmation_gate(
        self,
        name: str,
        semantic: dict[str, Any],
        arguments: dict[str, Any],
        principal: Principal,
        summary: str,
    ) -> dict[str, Any] | None:
        # ADR-0003: non-destructive writes require an honest-client confirmation
        # step. Returns None when already confirmed; otherwise returns a
        # confirmation-required payload carrying a token bound to this exact action.
        provided = arguments.get("confirm")
        ok, fail_reason = self._confirm.verify(principal, name, semantic, provided)
        if ok:
            return None
        confirmation_id = self._confirm.issue(principal, name, semantic)
        response: dict[str, Any] = {
            "confirmationRequired": True,
            "confirmationId": confirmation_id,
            "action": name,
            "arguments": _echo_args(semantic),
            "summary": summary,
            "instructions": (
                'Re-call this tool with the arguments you sent — UNABRIDGED; long text is digested in the '
                'echo above for display only, and the confirmation is bound to the full value — plus '
                '"confirm": "<confirmationId>" to proceed.'
            ),
        }
        if fail_reason is not None:
            # A confirm was actually supplied and didn't resolve -- say why, instead
            # of letting a failed retry look identical to an ordinary first call.
            response["confirmError"] = fail_reason
        return response

    def _enforce_read_quota(self, principal: Principal) -> None:
        quota = self._memory_write_limiter.check_read(principal)
        if not quota.allowed:
            raise PermissionError(quota.reason)

    def _audit(
        self,
        tool_name: str,
        principal: Principal,
        request_id: str,
        decision: PolicyDecision,
        outcome: str,
        *,
        start: float | None = None,
        resource_id: str | None = None,
        backend_status: str | None = None,
    ) -> None:
        duration_ms = int((time.monotonic() - start) * 1000) if start is not None else None
        self._audit_sink.write(
            AuditEvent(
                request_id=request_id,
                actor=principal.actor,
                project=principal.project,
                tool=tool_name,
                decision=decision.decision,
                outcome=outcome,
                reason=decision.reason,
                resource_id=resource_id,
                backend_status=backend_status,
                duration_ms=duration_ms,
            )
        )


def tool_definitions() -> list[dict[str, Any]]:
    return [
        {
            "name": "memory.search",
            "description": (
                "Search this project's memories — the recall path. Keyword matching, so identifiers, "
                "error codes and jargon work well; use memory.list only when you want the whole corpus."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "minLength": 1},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
        },
        {
            "name": "memory.save",
            "description": (
                "Save ONE atomic durable fact in 1-3 sentences — a decision and why, a root cause and "
                "fix, or a constraint not visible in the code. NOT a progress/session report, NOT an "
                "action's status (the board has it), NOT what git already records; long supporting "
                "evidence belongs in a document, and memory keeps the conclusion. Append-only and "
                "team-visible (actor recorded for audit)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "minLength": 1},
                    "tags": {"type": "array", "items": {"type": "string"}, "maxItems": 20},
                },
                "required": ["text"],
                "additionalProperties": False,
            },
        },
        {
            "name": "memory.list",
            "description": (
                "List this project's memories, newest first, paginated (each item carries its actor tag). "
                "Audit/report use — wrap-ups, \"who wrote what\". For recall use memory.search instead: it "
                "returns what is relevant rather than the whole corpus."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
                    "offset": {"type": "integer", "minimum": 0},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "memory.lesson_save",
            "description": (
                "Save a project-scoped 'never do this again' rule; persists across sessions. Use when the "
                "user corrects a mistake worth not repeating."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "rule": {"type": "string", "minLength": 1, "description": "Imperative rule, e.g. 'Always run lint before committing'."},
                    "reason": {"type": "string", "description": "Why it matters (optional)."},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1, "description": "0-1 (default 0.8)."},
                },
                "required": ["rule"],
                "additionalProperties": False,
            },
        },
        {
            "name": "memory.lesson_list",
            "description": "List this project's lessons (confidence-scored rules), highest confidence first.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "memory.action_create",
            "description": (
                "Create a project-scoped follow-up (status starts 'pending'; persists across sessions). "
                "Lighter than an issue — use issues.* for formal tickets."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "minLength": 1},
                    "description": {"type": "string"},
                    "priority": {"type": "string", "description": "e.g. low / medium / high (optional)."},
                },
                "required": ["title"],
                "additionalProperties": False,
            },
        },
        {
            "name": "memory.action_list",
            "description": (
                "List this project's OPEN actions (pending/active/blocked) — the live follow-up board. "
                "includeDone:true adds completed ones (for reports)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
                    "includeDone": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "memory.action_update_status",
            "description": (
                "Advance an action pending -> active -> done/blocked, so action_list stays a live board. "
                "Scoped to your project (an action id from another project is rejected)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action_id": {"type": "string", "minLength": 1},
                    "status": {"type": "string", "enum": ["active", "done", "blocked"]},
                },
                "required": ["action_id", "status"],
                "additionalProperties": False,
            },
        },
        {
            "name": "issues.get",
            "description": "Get one issue by id (scoped to your project).",
            "inputSchema": {
                "type": "object",
                "properties": {"id": {"type": ["string", "integer"]}},
                "required": ["id"],
                "additionalProperties": False,
            },
        },
        {
            "name": "issues.search",
            "description": "Search this project's issues by status/assignee.",
            "inputSchema": {
                "type": "object",
                "properties": {
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
                    "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20},
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "issues.mine",
            "description": (
                "Issues in this project assigned to you. Identity comes from your own enrolled tracker "
                "credential — the shared service credential cannot stand in for you, so this fails with "
                "setup instructions rather than returning someone else's issues."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20}},
                "additionalProperties": False,
            },
        },
        {
            "name": "issues.categories",
            "description": (
                "This project's issue categories (id + name), fetched live. Call this for the valid values of "
                "the `category` argument on issues.create / issues.update_status — categories are per-project "
                "and change over time, so there is no fixed list to guess from. Redmine only: GitLab has no "
                "category concept (it uses labels) and says so."
            ),
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "issues.create",
            "description": (
                "Create an issue in your project. Non-destructive write: the first call returns a "
                "confirmationId; re-call with the same arguments plus \"confirm\" to commit."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
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
                    "assignee": {
                        "type": "string",
                        "description": "Optional numeric user id (GitLab also accepts a username).",
                    },
                    "dueDate": {"type": "string", "description": "Optional YYYY-MM-DD. Redmine only."},
                    "priority": {
                        "type": "string",
                        "description": (
                            "Optional priority name this tracker defines (a stock Redmine has low / normal / "
                            "high / urgent / immediate); the project's own default applies when omitted. "
                            "An unknown name is rejected with the list this instance offers. Redmine only."
                        ),
                    },
                    "parentIssue": {
                        "type": ["string", "integer"],
                        "description": "Optional parent issue id — must be in this project. Redmine only.",
                    },
                    "category": {
                        "type": "string",
                        "description": (
                            "Optional category name from this project — call issues.categories for the valid "
                            "values, they are per-project and not a fixed set. Redmine only."
                        ),
                    },
                    "confirm": {"type": "string"},
                },
                "required": ["subject"],
                "additionalProperties": False,
            },
        },
        {
            "name": "issues.add_note",
            "description": "Add a note to an issue in your project. Non-destructive write: requires confirm (see issues.create).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {"type": ["string", "integer"]},
                    "note": {"type": "string", "minLength": 1},
                    "confirm": {"type": "string"},
                },
                "required": ["id", "note"],
                "additionalProperties": False,
            },
        },
        {
            "name": "issues.update_status",
            "description": "Update an issue's status (and optional doneRatio) in your project. Non-destructive write: requires confirm.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {"type": ["string", "integer"]},
                    "status": {
                        "type": "string",
                        "description": (
                            "A status name this tracker defines (normalized, e.g. \"IN_PROGRESS\"). An "
                            "unknown name is rejected with the list this instance offers."
                        ),
                    },
                    "doneRatio": {"type": "integer", "minimum": 0, "maximum": 100, "description": "Redmine only."},
                    "assignee": {
                        "type": "string",
                        "description": "Optional numeric user id (GitLab also accepts a username).",
                    },
                    "dueDate": {"type": "string", "description": "Optional YYYY-MM-DD. Redmine only."},
                    "priority": {
                        "type": "string",
                        "description": (
                            "Optional priority name this tracker defines; an unknown name is rejected with "
                            "the list this instance offers. Redmine only."
                        ),
                    },
                    "parentIssue": {
                        "type": ["string", "integer"],
                        "description": "Optional parent issue id — must be in this project. Redmine only.",
                    },
                    "category": {
                        "type": "string",
                        "description": (
                            "Optional category name from this project — call issues.categories for the valid "
                            "values. Redmine only."
                        ),
                    },
                    "confirm": {"type": "string"},
                },
                "required": ["id", "status"],
                "additionalProperties": False,
            },
        },
        {
            "name": "docs.search",
            "description": (
                "Keyword-search this project's docs corpus (reviewed markdown). Returns "
                "path/title/snippet/commit; full text via docs.get."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 25, "default": 8},
                },
                "required": ["query"],
                "additionalProperties": False,
            },
        },
        {
            "name": "docs.list",
            "description": (
                "List every document in the docs corpus (path/title/updated, plus status/staleAfter "
                "when declared — a deprecated or stale document can be skipped without fetching it). "
                "Use docs.search for relevance."
            ),
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "docs.get",
            "description": (
                "Fetch one document by path (as returned by docs.search/docs.list): full text + "
                "frontmatter + the corpus commit, and who created and last changed it."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        },
        {
            "name": "ci.status",
            "description": "Last-build status of this project's CI jobs (read-only).",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "ci.log",
            "description": "Tail of the last build's console log for one CI job (read-only, size-capped).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "job": {"type": "string"},
                    "lines": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 200},
                },
                "required": ["job"],
                "additionalProperties": False,
            },
        },
        {
            "name": "ci.artifact",
            "description": (
                "List one build's artifacts for a CI job: fileName, relativePath and a gateway "
                "download URL per file. Metadata only — fetch a file from the download URL with "
                "your existing bearer token; the bytes never travel through this tool, so a "
                "100 MB image cannot land in your context."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "job": {"type": "string"},
                    "build": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Build number; omitted means the last successful build.",
                    },
                },
                "required": ["job"],
                "additionalProperties": False,
            },
        },
    ]


def visible_tool_definitions(
    principal: Principal, issue_enabled: bool, docs_enabled: bool = False, ci_enabled: bool = False
) -> list[dict[str, Any]]:
    # Advertise only the tools this principal could actually call: issue tools need
    # the backend configured and an issue_project, and issue writes need the write
    # role; docs tools need a corpus configured for this project. This keeps
    # tools/list aligned with policy (discovery is not a security boundary —
    # handle_tool_call still re-checks policy).
    visible: list[dict[str, Any]] = []
    for tool in tool_definitions():
        name = tool["name"]
        if name in _ISSUE_TOOLS:
            if not (issue_enabled and principal.issue_project):
                continue
            if name in _ISSUE_WRITE_TOOLS and _ISSUE_WRITE_ROLE not in principal.roles:
                continue
        if name in _DOCS_TOOLS and not docs_enabled:
            continue
        if name in _CI_TOOLS and not ci_enabled:
            continue
        visible.append(tool)
    return visible


def _required_text(arguments: dict[str, Any], key: str, max_len: int) -> str:
    value = arguments.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"'{key}' must be a non-empty string")
    if len(value) > max_len:
        raise ValueError(f"'{key}' is too long")
    return value.strip()


def _limit(value: Any, default: int) -> int:
    if value is None:
        return default
    if not isinstance(value, int):
        raise ValueError("'limit' must be an integer")
    if value < 1 or value > 50:
        raise ValueError("'limit' must be between 1 and 50")
    return value


def _offset(value: Any) -> int:
    if value is None:
        return 0
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("'offset' must be an integer")
    if value < 0:
        raise ValueError("'offset' must be >= 0")
    return value


def _confidence(value: Any, default: float = 0.8) -> float:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("'confidence' must be a number between 0 and 1")
    if not 0 <= value <= 1:
        raise ValueError("'confidence' must be between 0 and 1")
    return float(value)


def _tags(value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("'tags' must be a list of strings")
    if len(value) > 20:
        raise ValueError("'tags' must contain at most 20 items")
    return [item.strip() for item in value if item.strip()]


def _required_issue_ref(arguments: dict[str, Any], key: str) -> str:
    value = arguments.get(key)
    if isinstance(value, int):
        value = str(value)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"'{key}' must be a non-empty string or integer")
    return value.strip()


def _optional_text(arguments: dict[str, Any], key: str, max_len: int) -> str | None:
    value = arguments.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"'{key}' must be a string")
    if len(value) > max_len:
        raise ValueError(f"'{key}' is too long")
    stripped = value.strip()
    return stripped or None


def _optional_int(arguments: dict[str, Any], key: str, *, minimum: int, maximum: int) -> int | None:
    value = arguments.get(key)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"'{key}' must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"'{key}' must be between {minimum} and {maximum}")
    return value


def _planning_texts(planning: dict[str, Any]) -> list[str]:
    """The planning values as strings, for the secret scan. They are short and
    structured, which is not the same as unable to carry a credential."""
    return [v if isinstance(v, str) else str(v) for v in planning.values()]


def _planning_fields(arguments: dict[str, Any]) -> dict[str, Any]:
    """dueDate / priority / parentIssue / category — shared by issues.create and
    issues.update_status.

    Only shape is checked here; the backend owns the meaning (a real calendar date,
    a priority this tracker defines, a parent resolvable inside this project, a
    category name resolvable against that project's live list — categories are
    per-project and member-editable, so there is no fixed enum to validate here).
    """
    planning: dict[str, Any] = {}
    due_date = _optional_text(arguments, "dueDate", max_len=10)
    if due_date is not None:
        planning["dueDate"] = due_date
    priority = _optional_text(arguments, "priority", max_len=60)
    if priority is not None:
        planning["priority"] = priority
    if arguments.get("parentIssue") is not None:
        planning["parentIssue"] = _required_issue_ref(arguments, "parentIssue")
    category = _optional_text(arguments, "category", max_len=80)
    if category is not None:
        planning["category"] = category
    return planning


_ECHO_MAX_CHARS = 200


def _echo_args(value: Any) -> Any:
    """Digest long free text in the confirmation echo.

    The echo exists so the caller can see the NORMALIZED arguments — what the
    gateway will actually do once defaults are applied. It is not what makes the
    gate safe: the confirmation id is bound to a server-side hash of the full
    canonical arguments, and the caller must resend them unabridged to confirm.
    Repeating a long body here would make a gated write pay for its own content
    three times (send, echo, resend), so anything past a couple of lines becomes
    a length + digest instead. Short fields still echo verbatim — those are the
    ones a caller cannot predict.
    """
    if isinstance(value, str) and len(value) > _ECHO_MAX_CHARS:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
        return f"<{len(value)} chars, sha256:{digest}>"
    if isinstance(value, dict):
        return {k: _echo_args(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_echo_args(v) for v in value]
    return value


def _tool_result(structured: dict[str, Any]) -> dict[str, Any]:
    text = json.dumps(structured, ensure_ascii=False, sort_keys=True)
    return {"content": [{"type": "text", "text": text}], "structuredContent": structured}


def _tool_error(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
