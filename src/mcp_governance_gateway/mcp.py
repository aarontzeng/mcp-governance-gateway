"""The MCP surface: JSON-RPC lifecycle, `tools/list`, and the `tools/call` boundary.

What lives here is what every tool call passes through and no tool owns: the
policy decision, the argument-name check, the confirmation gate, the error
boundary that turns a backend failure into a tool error rather than a 500,
and the audit line. What a tool DOES lives in `tools/<family>.py`, and what a
tool IS -- name, schema, role, the features it needs -- in one `ToolSpec`
there, which `policy.py` and discovery read from as well.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any

from . import __version__
from .audit import AuditEvent, AuditSink
from .auth import Principal
from .ci_backend import JenkinsHttpBackend
from .confirm import ConfirmationStore
from .docs_assets import AssetStage
from .docs_backend import DocsCorpus
from .docs_review import DocsReviewService
from .errors import BackendError
from .issue_backend import IssueBackend
from .limits import InMemoryMemoryWriteLimiter, MemoryLimitConfig, MemoryWriteLimiter
from .memory_backend import MemoryBackend, RequestContext
from .policy import Policy, PolicyDecision
from .tools import HANDLERS, SPECS_BY_NAME, tool_definitions, visible_tool_definitions, visible_tools
from .tools.base import (
    FEATURE_CI,
    FEATURE_CI_WRITE,
    FEATURE_DOCS,
    FEATURE_DOCS_REVIEW,
    FEATURE_DOCS_STAGE,
    FEATURE_ISSUES,
)

PROTOCOL_VERSION = "2025-06-18"

# Importers written against the pre-split module.
__all__ = [
    "GatewayApp",
    "PROTOCOL_VERSION",
    "Policy",
    "PolicyDecision",
    "tool_definitions",
    "visible_tool_definitions",
]


class GatewayApp:
    """One MCP server, over whatever backends this deployment configured.

    The public attributes are the `tools.ToolHost` contract: a handler in
    `tools/` reaches its backend and the two cross-cutting gates through them,
    and nothing else -- the audit sink and the policy stay this class's own.
    """

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
        docs_review: DocsReviewService | None = None,
        asset_stage: AssetStage | None = None,
    ) -> None:
        self.memory_backend = memory_backend
        self.issue_backend = issue_backend
        self.docs_corpus = docs_corpus
        # None unless a review host is configured for at least one project. The
        # docs read tools do not need it, which is why the corpus and the write
        # path are two objects rather than one.
        self.docs_review = docs_review
        self.asset_stage = asset_stage
        self.ci_backend = ci_backend
        self.write_limiter = memory_write_limiter or InMemoryMemoryWriteLimiter(MemoryLimitConfig())
        self._audit_sink = audit_sink
        self._policy = policy or Policy()
        self._confirm = confirmation or ConfirmationStore()

    # ------------------------------------------------------------ JSON-RPC

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

        if request_id is None:
            return None   # a notification (notifications/initialized, or any other) gets no reply

        if method == "initialize":
            return _result(request_id, self._initialize(params))
        if method == "ping":
            return _result(request_id, {})
        if method == "tools/list":
            tools = [spec.definition for spec in visible_tools(principal, self.enabled_features(principal))]
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

    def enabled_features(self, principal: Principal) -> set[str]:
        """Which deployment features this principal's project has, for
        `tools/list`. Discovery is not a security boundary -- policy re-checks
        every call -- so this only keeps the list honest."""
        features: set[str] = set()
        if self.issue_backend is not None:
            features.add(FEATURE_ISSUES)
        if self.docs_corpus is not None and self.docs_corpus.has_project(principal.project):
            features.add(FEATURE_DOCS)
        if self.docs_review is not None and self.docs_review.has_project(principal.project):
            features.add(FEATURE_DOCS_REVIEW)
        if self.asset_stage is not None:
            features.add(FEATURE_DOCS_STAGE)
        if self.ci_backend is not None and self.ci_backend.has_project(principal.project):
            features.add(FEATURE_CI)
            if self.ci_backend.has_trigger_project(principal.project):
                features.add(FEATURE_CI_WRITE)
        return features

    # ---------------------------------------------------------- tools/call

    def _handle_tool_call(self, request_id: Any, params: dict[str, Any], principal: Principal) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return _error(request_id, -32602, "Invalid tool call params")

        gateway_request_id = str(uuid.uuid4())
        start = time.monotonic()
        spec = SPECS_BY_NAME.get(name)
        # An undeclared name is audited under a fixed label: the tool field is
        # the one caller-chosen string that reaches the audit log verbatim, and a
        # credential pasted there by mistake would sit in an append-only log
        # forever. The error carries a fixed reason, never the name.
        audit_name = name if spec is not None else "unknown"
        decision = self._policy.decide(name, principal)
        if not decision.allowed:
            self._audit(audit_name, principal, gateway_request_id, decision, "denied", start=start)
            return _error(request_id, -32003, decision.reason)
        assert spec is not None   # policy allows nothing the registry does not know

        context = RequestContext.from_principal(principal, gateway_request_id)
        try:
            # Every schema says `additionalProperties: false`; enforce it here so an
            # argument the schema does not name is refused rather than ignored.
            undeclared = sorted(key for key in arguments if key not in spec.arguments)
            if undeclared:
                raise ValueError(f"unknown argument(s) for {name}: {', '.join(undeclared)}")
            result = HANDLERS[spec.family](self, name, arguments, principal, context)
        except ValueError as exc:
            self._audit(name, principal, gateway_request_id, decision, "invalid", start=start)
            return _error(request_id, -32602, str(exc))
        except PermissionError as exc:
            denied = PolicyDecision("deny", str(exc))
            self._audit(name, principal, gateway_request_id, denied, "denied", start=start)
            return _error(request_id, -32003, str(exc))
        except BackendError as exc:
            backend_status = str(exc.status) if exc.status is not None else "error"
            self._audit(
                name, principal, gateway_request_id, decision, "backend_error",
                start=start, backend_status=backend_status,
            )
            return _result(request_id, _tool_error(str(exc)))

        if isinstance(result, dict) and result.get("confirmationRequired"):
            self._audit(name, principal, gateway_request_id, decision, "confirm_required", start=start)
            return _result(request_id, _tool_result(result))

        # `id` for the backends that create a numbered thing; `queueItem` for
        # ci.rerun, whose queue item IS what the call created. A spec whose
        # handle is neither says so itself.
        resource_id: str | None = None
        if isinstance(result, dict):
            resource_id = (spec.resource_id(result) if spec.resource_id is not None
                           else result.get("id") or result.get("queueItem"))
        self._audit(
            name, principal, gateway_request_id, decision, "ok",
            start=start, backend_status="ok", resource_id=resource_id,
        )
        return _result(request_id, _tool_result(result))

    # ------------------------------------------------- the ToolHost contract

    def confirmation_gate(
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

    def enforce_read_quota(self, principal: Principal) -> None:
        quota = self.write_limiter.check_read(principal)
        if not quota.allowed:
            raise PermissionError(quota.reason)

    # ----------------------------------------------------------------- audit

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
