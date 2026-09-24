"""Files the gateway reads while something else writes them.

Two halves of one contract. `atomic_write_json` is how a writer replaces such
a file: a temp file in the same directory, 0600 before any bytes, fsync, then
`os.replace`, so a reader sees the old file or the new one and never a partial
one -- and a NEW inode every time, which is what the other half detects.

`ReloadingFile` is how a reader keeps up: it re-parses when the file's
`(st_mtime_ns, st_size, st_ino)` signature changes. All three fields, because
`st_mtime` alone misses two same-second writes on a coarse-mtime filesystem
and the inode is what an atomic replace changes for certain. Five modules
each carried their own copy of this loop before, and no two agreed on what
a corrupt file meant: one retried it on every call, one kept it silently,
one read it with no lock at all. The policy lives here now, once:

- A parse failure keeps the LAST-GOOD value. A botched write must never lock
  everyone out or take a backend down. That is fail-open for an allow-list
  (a removed grant or token is still live), so it is never silent: it is
  logged, throttled, and surfaced as `stale` for a health check to report.
- Whether the failed signature is recorded decides when the retry happens.
  Recorded (the default): on the next change to the file. Not recorded
  (`retry_failed=True`): on every access, which is right for a mapping whose
  staleness is a tenancy question rather than an availability one.
- Reloads are serialized and the signature re-read under the lock, so two
  requests that both saw a change cannot publish the OLDER version last.
  Reads take no lock: the value is rebound, never mutated in place.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Generic, TypeVar

T = TypeVar("T")

_UNSET = object()   # can never equal a real signature, so the first access reloads


def file_signature(path: str | Path) -> tuple:
    """`(st_mtime_ns, st_size, st_ino)`, or a None-triple for a file that cannot
    be stat'd -- which is itself a state worth noticing a change into."""
    try:
        st = os.stat(path)
    except OSError:
        return (None, None, None)
    return (st.st_mtime_ns, st.st_size, st.st_ino)


class ReloadingFile(Generic[T]):
    """A parsed value that follows one file (or several) on disk.

    `parse` reads and parses whatever the value is built from; it receives the
    previous value so a parser that versions its result (a generation counter)
    can. It runs outside the lock's hot path -- at most one thread at a time,
    with the others using the last-good value meanwhile.

    `load_now=True` parses at construction and lets a failure propagate: for a
    file that must be readable at boot (an allow-list with no last-good yet).
    Otherwise the first access parses lazily, and `initial` is what counts as
    last-good until then. The signature is deliberately NOT stamped at
    construction from a value the caller parsed earlier: an edit landing
    between that read and this stamp would be recorded as already seen and
    never picked up, so the first access always reloads once.
    """

    _COMPLAIN_EVERY_SEC = 30.0

    def __init__(
        self,
        paths: Sequence[str | Path] | str | Path | None,
        parse: Callable[[T], T],
        *,
        what: str,
        initial: T,
        load_now: bool = False,
        retry_failed: bool = False,
        failure_message: str | None = None,
    ) -> None:
        if paths is None:
            self._paths: tuple[Path, ...] = ()
        elif isinstance(paths, (str, Path)):
            self._paths = (Path(paths),)
        else:
            self._paths = tuple(Path(p) for p in paths)
        self._parse = parse
        self._what = what
        self._failure_message = failure_message or f"{what} reload failed; keeping the last-good copy"
        self._retry_failed = retry_failed
        self._lock = threading.Lock()
        self._value: T = initial
        # No paths means a static value: its signature is () from the start, so
        # nothing ever differs from it.
        self._sig: object = () if not self._paths else _UNSET
        self._stale = False
        self._last_complaint = 0.0
        if load_now:
            self._value = self._parse(initial)
            self._sig = self._signature()

    @property
    def paths(self) -> tuple[Path, ...]:
        return self._paths

    @property
    def stale(self) -> bool:
        """The last parse failed, so the live value may be out of date."""
        return self._stale

    @property
    def value(self) -> T:
        """The last published value, without checking the file. For a caller
        that must observe the live state rather than repair it."""
        return self._value

    @property
    def current(self) -> T:
        """The value, reloaded first if the file changed."""
        self.refresh()
        return self._value

    def _signature(self) -> tuple:
        return tuple(file_signature(p) for p in self._paths)

    def refresh(self) -> None:
        if not self._paths or self._signature() == self._sig:
            return
        with self._lock:
            signature = self._signature()   # re-read under the lock: see the module docstring
            if signature == self._sig:
                return
            try:
                value = self._parse(self._value)
            except Exception as exc:  # noqa: BLE001 - any failure keeps last-good
                self._stale = True
                if not self._retry_failed:
                    self._sig = signature
                now = time.monotonic()
                if now - self._last_complaint > self._COMPLAIN_EVERY_SEC:
                    self._last_complaint = now
                    print(f"{self._failure_message}: {exc}", file=sys.stderr, flush=True)
                return
            self._value = value
            self._sig = signature
            self._stale = False

    def publish(self, value: T) -> None:
        """Record a value this process just wrote itself, stamped with the file's
        signature as it now is, so the write is not re-read as a change."""
        with self._lock:
            self._value = value
            self._sig = self._signature()
            self._stale = False


def atomic_write_json(path: str | Path, payload: Any, *, mode: int = 0o600) -> None:
    """Replace `path` with `payload` as JSON: atomically, `mode` before any bytes,
    fsynced. The temp file is created in the SAME directory so `os.replace` is a
    rename within one filesystem; across filesystems it is not atomic. The mode
    is set before the bytes, not after, so a secret is never briefly readable by
    anyone else, and an existing file is tightened on its next write."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
        tmp = ""
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
