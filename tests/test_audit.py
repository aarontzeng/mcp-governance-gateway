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


class _GatedStream:
    """A stream whose write blocks in the middle, so a second writer can be
    observed entering it. `TextIOWrapper.write` does not give a test that hook."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.entered = threading.Event()
        self.release = threading.Event()
        self._inside = 0
        self._lock = threading.Lock()
        self.overlapped = False

    def write(self, data: str) -> int:
        with self._lock:
            self._inside += 1
            if self._inside > 1:
                self.overlapped = True
        self.entered.set()
        self.release.wait(timeout=2)
        self.lines.append(data)
        with self._lock:
            self._inside -= 1
        return len(data)

    def flush(self) -> None:
        return


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
        stream = _GatedStream()
        sink = JsonLinesAuditSink(stream)
        arrived = threading.Event()
        first = threading.Thread(target=lambda: sink.write(_event("r1")))
        first.start()
        self.assertTrue(stream.entered.wait(timeout=2), "first writer did not enter the stream")

        def second_write() -> None:
            arrived.set()
            sink.write(_event("r2"))

        second = threading.Thread(target=second_write)
        second.start()
        self.assertTrue(arrived.wait(timeout=2))
        # The second writer has been scheduled. Give it long enough to reach
        # the stream; with the sink lock held by the first writer it must not.
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline and not stream.overlapped:
            time.sleep(0.01)
        try:
            self.assertFalse(stream.overlapped)
        finally:
            stream.release.set()
            first.join(timeout=2)
            second.join(timeout=2)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(
            [json.loads(line)["requestId"] for line in stream.lines],
            ["r1", "r2"],
        )


if __name__ == "__main__":
    unittest.main()
