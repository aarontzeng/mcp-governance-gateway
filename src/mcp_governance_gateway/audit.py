from __future__ import annotations

import json
import sys
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, TextIO


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


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
    """One JSON object per line on a stream shared by every request thread.

    `ThreadingHTTPServer` handles requests concurrently, and a `TextIO` write
    is not atomic: two `write` calls can interleave inside the buffer and two
    flushes can split a line across the underlying file. The line is built
    before the lock so the JSON work does not stall the other writers; the
    lock covers the write and the flush together, which is what keeps one
    record one line.
    """

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream if stream is not None else sys.stdout
        self._lock = threading.Lock()

    def write(self, event: AuditEvent) -> None:
        line = json.dumps(event.to_json(), ensure_ascii=False) + "\n"
        with self._lock:
            self._stream.write(line)
            self._stream.flush()


class ListAuditSink(AuditSink):
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)
