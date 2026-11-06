"""The audit stream is one JSON object per line, including under concurrency."""
from __future__ import annotations

import json
import threading
import time
import unittest

from mcp_governance_gateway.audit import AuditEvent, JsonLinesAuditSink


def _event(request_id: str) -> AuditEvent:
    return AuditEvent(
        request_id=request_id, actor="a", project="p", tool="memory.search",
        decision="allow", outcome="ok", reason="phase1 memory tool",
    )


class _MeetingStream:
    """A stream that records every operation in order and makes overlap observable by a POSITIVE signal.

    Each write waits at a two-party barrier: if a second writer is inside the stream at the same time, both pass at once
    (`overlapped`); if the sink serialises writers, the first one's wait times out. flush sleeps briefly, giving a writer
    that was let in between a write and its flush time to show itself in `ops`."""

    def __init__(self, meeting_timeout: float = 1.0) -> None:
        self.ops: list[str] = []
        self.overlapped = False
        self._barrier = threading.Barrier(2, timeout=meeting_timeout)
        self._lock = threading.Lock()

    def write(self, data: str) -> int:
        request_id = json.loads(data)["requestId"]
        with self._lock:
            self.ops.append(f"write:{request_id}")
        try:
            self._barrier.wait()
            self.overlapped = True
        except threading.BrokenBarrierError:
            pass
        return len(data)

    def flush(self) -> None:
        time.sleep(0.05)
        with self._lock:
            self.ops.append("flush")


class JsonLinesAuditSinkTests(unittest.TestCase):
    def test_each_event_is_one_json_line(self) -> None:
        import io

        buf = io.StringIO()
        sink = JsonLinesAuditSink(buf)
        sink.write(_event("r1"))
        sink.write(_event("r2"))
        lines = buf.getvalue().splitlines()
        self.assertEqual([json.loads(line)["requestId"] for line in lines], ["r1", "r2"])

    def test_concurrent_writes_do_not_enter_the_stream_together(self) -> None:
        stream = _MeetingStream()
        sink = JsonLinesAuditSink(stream)
        second_has_its_line = threading.Event()

        class SignallingEvent(AuditEvent):
            def to_json(self):
                second_has_its_line.set()      # the line is built before the sink lock: the writer is about to take it
                return super().to_json()

        second_event = SignallingEvent(
            request_id="r2", actor="a", project="p", tool="memory.search",
            decision="allow", outcome="ok", reason="phase1 memory tool",
        )

        def second_write() -> None:
            sink.write(second_event)

        first = threading.Thread(target=lambda: sink.write(_event("r1")))
        second = threading.Thread(target=second_write)
        first.start()
        deadline = time.monotonic() + 2
        while "write:r1" not in stream.ops and time.monotonic() < deadline:
            time.sleep(0.005)
        second.start()
        self.assertTrue(second_has_its_line.wait(timeout=2), "second writer never reached the sink")
        first.join(timeout=5)
        second.join(timeout=5)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertFalse(stream.overlapped, "a second writer was inside the stream while the first was")
        # one record = write then its own flush, with nothing in between: the lock covers both
        self.assertEqual(stream.ops, ["write:r1", "flush", "write:r2", "flush"])


if __name__ == "__main__":
    unittest.main()
