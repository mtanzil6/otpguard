from __future__ import annotations

import math
from typing import Any, Protocol


class StoreError(RuntimeError):
    """Raised when the backing store can't be reached."""


def minute(ts: float) -> int:
    return int(ts // 60)


def hour(ts: float) -> int:
    return int(ts // 3600)


def hours_for(minutes: int) -> int:
    return max(1, math.ceil(minutes / 60))


class Store(Protocol):
    """Everything the detectors need from storage. Time is always passed in, so the
    same code runs live and in replay."""

    def incr(self, key: str, ts: float, amount: float = 1.0) -> None:
        """Add to a counter in the minute and hour buckets that contain ``ts``."""

    def window_sum(self, key: str, ts: float, minutes: int) -> float:
        """Sum of a counter over the last ``minutes`` (minute buckets up to two hours,
        hour buckets beyond that)."""

    def reserve(self, key: str, ts: float, windows: list[tuple[int, float]],
                amount: float = 1.0) -> tuple[bool, list[float]]:
        """Atomically check-and-increment. ``windows`` is a list of (minutes, limit):
        the counter is incremented by ``amount`` only if, for every window, the
        current sum plus ``amount`` is at or below the limit. Returns (ok, sums before
        the increment, one per window). On Redis this is one Lua script, so concurrent
        requests on different servers cannot race past a cap."""

    def add_unique(self, key: str, member: str, ts: float, ttl_s: int) -> bool:
        """Remember ``member``; True if it was not already known."""

    def set_add(self, key: str, member: str, ttl_s: int) -> bool:
        """Add to a plain set; True if it was new."""

    def set_members(self, key: str) -> list[str]: ...

    def hll_add(self, key: str, member: str, ttl_s: int) -> None: ...

    def hll_count(self, key: str) -> int: ...

    def push_ts(self, key: str, ts: float, maxlen: int, ttl_s: int) -> None: ...

    def get_ts(self, key: str) -> list[float]: ...

    def get_json(self, key: str) -> Any: ...

    def set_json(self, key: str, value: Any, ttl_s: int | None = None) -> None: ...

    def ping(self) -> bool: ...
