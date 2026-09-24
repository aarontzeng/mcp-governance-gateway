"""The one change-detected reload and the one atomic write, which five modules
used to each carry a copy of -- with five different answers to what a corrupt
file meant."""
from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import tempfile
import time
import unittest
from pathlib import Path

from mcp_governance_gateway.hotfile import (
    ReloadingFile,
    atomic_write_json,
    file_signature,
)


def _bump(path: Path) -> None:
    future = time.time() + 5
    os.utime(path, (future, future))


class ReloadingFileTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = Path(self.dir.name) / "value.json"
        self.path.write_text(json.dumps({"v": 1}), encoding="utf-8")
        self.parses = 0

    def _parse(self, previous):
        self.parses += 1
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _store(self, **kw) -> ReloadingFile[dict]:
        return ReloadingFile(self.path, self._parse, what="value", initial={"v": 0}, **kw)

    def test_the_first_access_reloads_even_when_the_caller_parsed_earlier(self):
        # The signature is not stamped at construction: an edit landing between
        # the caller's own read and the stamp would otherwise never be seen.
        store = self._store()
        self.assertEqual(store.value, {"v": 0})   # no check, no reload
        self.assertEqual(store.current, {"v": 1})
        self.assertEqual(store.current, {"v": 1})
        self.assertEqual(self.parses, 1)

    def test_a_changed_file_is_re_read_once(self):
        store = self._store()
        store.refresh()
        self.path.write_text(json.dumps({"v": 2}), encoding="utf-8")
        _bump(self.path)
        self.assertEqual(store.current, {"v": 2})
        store.refresh()
        self.assertEqual(self.parses, 2)

    def test_a_corrupt_file_keeps_the_last_good_value_and_says_so(self):
        store = self._store()
        store.refresh()
        self.path.write_text("{ nope", encoding="utf-8")
        _bump(self.path)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(store.current, {"v": 1})
            self.assertEqual(store.current, {"v": 1})
        self.assertTrue(store.stale)
        self.assertIn("value reload failed; keeping the last-good copy", err.getvalue())
        self.assertEqual(err.getvalue().count("reload failed"), 1, "complaints are throttled")
        self.assertEqual(self.parses, 2, "a recorded failure is not retried until the file changes")
        self.path.write_text(json.dumps({"v": 3}), encoding="utf-8")
        _bump(self.path)
        self.assertEqual(store.current, {"v": 3})
        self.assertFalse(store.stale)

    def test_retry_failed_re_reads_a_corrupt_file_on_every_access(self):
        # For an allow-list, last-good is fail-open, so a repair that lands with
        # an identical signature must still be picked up.
        store = self._store(retry_failed=True)
        store.refresh()
        self.path.write_text("{ nope", encoding="utf-8")
        _bump(self.path)
        with contextlib.redirect_stderr(io.StringIO()):
            store.refresh()
            store.refresh()
        self.assertEqual(self.parses, 3)
        self.assertTrue(store.stale)

    def test_load_now_parses_at_construction_and_lets_a_failure_propagate(self):
        self.path.write_text("{ nope", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            self._store(load_now=True)
        self.path.write_text(json.dumps({"v": 9}), encoding="utf-8")
        self.parses = 0
        store = self._store(load_now=True)
        self.assertEqual(store.value, {"v": 9})
        store.refresh()
        self.assertEqual(self.parses, 1, "the construction-time parse stamped the signature")

    def test_publish_records_a_write_of_our_own_without_re_reading_it(self):
        store = self._store()
        store.refresh()
        atomic_write_json(self.path, {"v": 7})
        store.publish({"v": 7})
        self.assertEqual(store.current, {"v": 7})
        self.assertEqual(self.parses, 1)

    def test_no_path_is_a_static_value(self):
        store: ReloadingFile[dict] = ReloadingFile(None, self._parse, what="static", initial={"v": 0})
        self.assertEqual(store.current, {"v": 0})
        self.assertEqual(self.parses, 0)

    def test_several_paths_share_one_signature(self):
        other = Path(self.dir.name) / "other.json"
        other.write_text("{}", encoding="utf-8")
        store: ReloadingFile[int] = ReloadingFile([self.path, other], lambda prev: prev + 1, what="pair", initial=0)
        self.assertEqual(store.current, 1)
        other.write_text("{ }", encoding="utf-8")
        _bump(other)
        self.assertEqual(store.current, 2)
        self.assertEqual(store.current, 2)

    def test_a_file_that_appears_later_is_a_change(self):
        missing = Path(self.dir.name) / "later.json"
        seen: list[int] = []

        def parse(prev):
            seen.append(1)
            return json.loads(missing.read_text(encoding="utf-8"))

        store: ReloadingFile[dict] = ReloadingFile(missing, parse, what="late", initial={})
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(store.current, {})   # missing: parse failed, last-good kept
        self.assertEqual(file_signature(missing), (None, None, None))
        missing.write_text(json.dumps({"here": True}), encoding="utf-8")
        self.assertEqual(store.current, {"here": True})


class AtomicWriteTests(unittest.TestCase):
    def test_mode_content_and_no_leftovers(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "nested" / "store.json"
            atomic_write_json(target, {"keys": {"a": 1}})
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), {"keys": {"a": 1}})
            self.assertTrue(target.read_text(encoding="utf-8").endswith("\n"))
            self.assertEqual(list(target.parent.glob(".*")), [], "temp file left behind")

    def test_a_replaced_file_has_a_new_inode_so_a_reader_notices(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "store.json"
            atomic_write_json(target, {"v": 1})
            before = file_signature(target)
            atomic_write_json(target, {"v": 1})   # same bytes, same size
            self.assertNotEqual(before[2], file_signature(target)[2])


if __name__ == "__main__":
    unittest.main()
