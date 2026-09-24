"""Scripted fakes shared by the gateway test files: the two backends every GatewayApp needs, and a canned urlopen response."""
from __future__ import annotations

import json

from mcp_governance_gateway.issue_backend import IssueBackend
from mcp_governance_gateway.memory_backend import MemoryBackend, RequestContext


class FakeMemoryBackend(MemoryBackend):
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def search(self, query: str, limit: int, context: RequestContext) -> dict[str, object]:
        self.calls.append({"tool": "search", "query": query, "limit": limit, **context.metadata()})
        return {"results": [{"observation": {"id": "obs_1"}}], "count": 1}

    def save(self, text: str, tags: list[str], context: RequestContext) -> dict[str, object]:
        self.calls.append({"tool": "save", "text": text, "tags": tags, **context.metadata()})
        return {"saved": True, "project": context.project, "id": "mem_1"}

    def list(self, limit: int, offset: int, context: RequestContext) -> dict[str, object]:
        self.calls.append({"tool": "list", "limit": limit, "offset": offset, **context.metadata()})
        return {
            "memories": [{"id": "mem_1", "project": context.project, "title": "t"}],
            "count": 1,
            "total": 1,
            "offset": offset,
            "truncated": False,
        }

    def lesson_save(self, rule: str, reason, confidence: float, context: RequestContext) -> dict[str, object]:
        self.calls.append({"tool": "lesson_save", "rule": rule, "reason": reason, "confidence": confidence, **context.metadata()})
        return {"saved": True, "project": context.project, "id": "lsn_1"}

    def lesson_list(self, limit: int, context: RequestContext) -> dict[str, object]:
        self.calls.append({"tool": "lesson_list", "limit": limit, **context.metadata()})
        return {"lessons": [{"id": "lsn_1", "project": context.project, "content": "c", "confidence": 0.9}], "count": 1}

    def action_create(self, title: str, description, priority, context: RequestContext) -> dict[str, object]:
        self.calls.append({"tool": "action_create", "title": title, "description": description, "priority": priority, **context.metadata()})
        return {"created": True, "project": context.project, "id": "act_1", "status": "pending"}

    def action_list(self, limit: int, context: RequestContext, include_done: bool = False) -> dict[str, object]:
        self.calls.append({"tool": "action_list", "limit": limit, "include_done": include_done, **context.metadata()})
        return {"actions": [{"id": "act_1", "project": context.project, "title": "t", "status": "pending"}], "count": 1}

    def action_update_status(self, action_id: str, status: str, context: RequestContext) -> dict[str, object]:
        self.calls.append({"tool": "action_update_status", "action_id": action_id, "status": status, **context.metadata()})
        return {"updated": True, "id": action_id, "status": status}


class FakeIssueBackend(IssueBackend):
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def get(self, issue_id, context):  # type: ignore[no-untyped-def]
        self.calls.append(("get", issue_id, context.redmine_project))
        return {"id": issue_id, "projectId": context.redmine_project, "subject": "x"}

    def search(self, filters, limit, context):  # type: ignore[no-untyped-def]
        self.calls.append(("search", filters, limit, context.redmine_project))
        return {"issues": [{"id": "1"}], "count": 1}

    def create(self, fields, context):  # type: ignore[no-untyped-def]
        self.calls.append(("create", fields, context.redmine_project))
        return {"created": True, "id": "99", "subject": fields["subject"]}

    def add_note(self, issue_id, note, context):  # type: ignore[no-untyped-def]
        self.calls.append(("add_note", issue_id, note))
        return {"noted": True, "id": issue_id}

    def update_status(self, issue_id, status, done_ratio, context, *, assignee=None, planning=None):  # type: ignore[no-untyped-def]
        self.calls.append(("update_status", issue_id, status, done_ratio, assignee, planning or {}))
        return {"updated": True, "id": issue_id, "status": status}

    def mine(self, limit, context):  # type: ignore[no-untyped-def]
        self.calls.append(("mine", limit, context.redmine_project))
        return {"issues": [{"id": "7"}], "count": 1}

    def categories(self, context):  # type: ignore[no-untyped-def]
        self.calls.append(("categories", context.redmine_project))
        return {"categories": [{"id": "3", "name": "Firmware"}], "count": 1}


class FakeResponse:
    def __init__(self, body: dict[str, object]) -> None:
        self._body = json.dumps(body).encode("utf-8")

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        return None

    def read(self, *args) -> bytes:  # type: ignore[no-untyped-def]
        return self._body
