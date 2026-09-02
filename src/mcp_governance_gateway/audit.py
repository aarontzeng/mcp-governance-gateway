from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import sys
from typing import Any, TextIO


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class AuditEvent:
    request_id: str
    actor: str
    project: str
    tool: str
    decision: str
    outcome: str
    reason: str
    resource_id: str | None = None
    backend_status: str | None = None
    duration_ms: int | None = None
    bytes_sent: int | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "ts": utc_now_iso(),
            "requestId": self.request_id,
            "actor": self.actor,
            "project": self.project,
            "tool": self.tool,
            "decision": self.decision,
            "outcome": self.outcome,
            "reason": self.reason,
            "resourceId": self.resource_id,
            "backendStatus": self.backend_status,
            "durationMs": self.duration_ms,
            "bytesSent": self.bytes_sent,
        }


class AuditSink:
    def write(self, event: AuditEvent) -> None:
        raise NotImplementedError


class JsonLinesAuditSink(AuditSink):
    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream if stream is not None else sys.stdout

    def write(self, event: AuditEvent) -> None:
        self._stream.write(json.dumps(event.to_json(), ensure_ascii=False) + "\n")
        self._stream.flush()


class ListAuditSink(AuditSink):
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)
