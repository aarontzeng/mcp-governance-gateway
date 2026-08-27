from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
import threading
import time
from typing import Callable

from .auth import Principal


@dataclass(frozen=True)
class LimitDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True)
class MemoryLimitConfig:
    max_save_text_bytes: int = 32_768
    user_writes_per_minute: int = 30
    project_writes_per_day: int = 5_000
    user_reads_per_minute: int = 120


class MemoryWriteLimiter:
    def check_and_record(self, principal: Principal, text: str) -> LimitDecision:
        raise NotImplementedError

    def check_read(self, principal: Principal) -> LimitDecision:
        raise NotImplementedError


class InMemoryMemoryWriteLimiter(MemoryWriteLimiter):
    def __init__(self, config: MemoryLimitConfig, clock: Callable[[], float] | None = None) -> None:
        self._config = config
        self._clock = clock or time.time
        self._lock = threading.Lock()
        self._user_minute_writes: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._user_minute_reads: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        # project -> (day_index, count); keyed by project only so it does not
        # accumulate one entry per project per day forever.
        self._project_day_writes: dict[str, tuple[int, int]] = {}

    def check_and_record(self, principal: Principal, text: str) -> LimitDecision:
        text_bytes = len(text.encode("utf-8"))
        if self._config.max_save_text_bytes > 0 and text_bytes > self._config.max_save_text_bytes:
            return LimitDecision(
                False,
                f"memory.save text exceeds {self._config.max_save_text_bytes} bytes",
            )

        now = self._clock()
        with self._lock:
            user_decision = self._check_user_minute_limit(principal, now)
            if not user_decision.allowed:
                return user_decision

            project_decision = self._check_project_day_limit(principal, now)
            if not project_decision.allowed:
                return project_decision

            if self._config.user_writes_per_minute > 0:
                self._user_minute_writes[(principal.actor, principal.project)].append(now)
            if self._config.project_writes_per_day > 0:
                day = _day_index(now)
                stored = self._project_day_writes.get(principal.project)
                count = stored[1] + 1 if stored is not None and stored[0] == day else 1
                self._project_day_writes[principal.project] = (day, count)

        return LimitDecision(True, "memory write within quota")

    def check_read(self, principal: Principal) -> LimitDecision:
        limit = self._config.user_reads_per_minute
        if limit <= 0:
            return LimitDecision(True, "per-user read rate disabled")

        now = self._clock()
        with self._lock:
            reads = self._user_minute_reads[(principal.actor, principal.project)]
            cutoff = now - 60
            while reads and reads[0] <= cutoff:
                reads.popleft()
            if len(reads) >= limit:
                return LimitDecision(False, f"per-user read rate exceeds {limit} memory read calls per minute")
            reads.append(now)
        return LimitDecision(True, "per-user read rate within quota")

    def _check_user_minute_limit(self, principal: Principal, now: float) -> LimitDecision:
        limit = self._config.user_writes_per_minute
        if limit <= 0:
            return LimitDecision(True, "per-user write rate disabled")

        writes = self._user_minute_writes[(principal.actor, principal.project)]
        cutoff = now - 60
        while writes and writes[0] <= cutoff:
            writes.popleft()
        if len(writes) >= limit:
            return LimitDecision(False, f"per-user write rate exceeds {limit} memory.save calls per minute")
        return LimitDecision(True, "per-user write rate within quota")

    def _check_project_day_limit(self, principal: Principal, now: float) -> LimitDecision:
        limit = self._config.project_writes_per_day
        if limit <= 0:
            return LimitDecision(True, "per-project daily quota disabled")

        stored = self._project_day_writes.get(principal.project)
        used = stored[1] if stored is not None and stored[0] == _day_index(now) else 0
        if used >= limit:
            return LimitDecision(False, f"per-project daily write quota exceeds {limit} memory.save calls")
        return LimitDecision(True, "per-project daily quota within quota")


def _day_index(timestamp: float) -> int:
    return int(timestamp // 86_400)
