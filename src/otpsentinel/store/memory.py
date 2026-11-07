from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

from .base import hour, hours_for, minute

_KEEP_MINUTES = 180        # minute buckets kept per counter
_KEEP_HOURS = 26 * 7       # hour buckets kept per counter (a week and a bit)


class MemoryStore:
    """In-process store for tests, replay and single-server setups."""

    def __init__(self) -> None:
        self._m: dict[str, dict[int, float]] = {}
        self._h: dict[str, dict[int, float]] = {}
        self._unique: dict[str, float] = {}
        self._hll: dict[str, set[str]] = {}
        self._sets: dict[str, tuple[set[str], float | None]] = {}
        self._lock = threading.Lock()
        self._ts: dict[str, deque[float]] = {}
        self._kv: dict[str, Any] = {}
        self._writes = 0
        self._now = 0.0

    # counters ---------------------------------------------------------------------
    def incr(self, key: str, ts: float, amount: float = 1.0) -> None:
        self._now = max(self._now, ts)
        m, h = minute(ts), hour(ts)
        mb = self._m.setdefault(key, {})
        mb[m] = mb.get(m, 0.0) + amount
        hb = self._h.setdefault(key, {})
        hb[h] = hb.get(h, 0.0) + amount
        if len(mb) > _KEEP_MINUTES * 2:
            for b in [b for b in mb if b < m - _KEEP_MINUTES]:
                del mb[b]
        if len(hb) > _KEEP_HOURS * 2:
            for b in [b for b in hb if b < h - _KEEP_HOURS]:
                del hb[b]
        self._writes += 1
        if self._writes % 200_000 == 0:
            self._gc()

    def window_sum(self, key: str, ts: float, minutes: int) -> float:
        if minutes <= 120:
            mb = self._m.get(key)
            if not mb:
                return 0.0
            m = minute(ts)
            lo = m - minutes + 1
            if len(mb) < minutes:
                return sum(v for b, v in mb.items() if lo <= b <= m)
            return sum(mb.get(b, 0.0) for b in range(lo, m + 1))
        hb = self._h.get(key)
        if not hb:
            return 0.0
        h = hour(ts)
        lo = h - hours_for(minutes) + 1
        return sum(v for b, v in hb.items() if lo <= b <= h)

    def reserve(self, key: str, ts: float, windows: list[tuple[int, float]],
                amount: float = 1.0) -> tuple[bool, list[float]]:
        with self._lock:
            sums = [self.window_sum(key, ts, w) for w, _ in windows]
            ok = all(s + amount <= limit for s, (_, limit) in zip(sums, windows))
            if ok:
                self.incr(key, ts, amount)
            return ok, sums

    # sets ---------------------------------------------------------------------------
    def set_add(self, key: str, member: str, ttl_s: int) -> bool:
        s, _ = self._sets.get(key, (None, None))
        if s is None:
            s = set()
        new = member not in s
        s.add(member)
        self._sets[key] = (s, (self._now or time.time()) + ttl_s if ttl_s else None)
        return new

    def set_members(self, key: str) -> list[str]:
        item = self._sets.get(key)
        if item is None:
            return []
        s, exp = item
        if exp is not None and exp < self._now:
            del self._sets[key]
            return []
        return list(s)

    def add_unique(self, key: str, member: str, ts: float, ttl_s: int) -> bool:
        k = f"{key}:{member}"
        exp = self._unique.get(k)
        self._unique[k] = ts + ttl_s
        return exp is None or exp < ts

    def hll_add(self, key: str, member: str, ttl_s: int) -> None:
        self._hll.setdefault(key, set()).add(member)

    def hll_count(self, key: str) -> int:
        return len(self._hll.get(key, ()))

    # lists and values ---------------------------------------------------------------
    def push_ts(self, key: str, ts: float, maxlen: int, ttl_s: int) -> None:
        q = self._ts.get(key)
        if q is None or q.maxlen != maxlen:
            q = deque(q or (), maxlen=maxlen)
            self._ts[key] = q
        q.append(ts)

    def get_ts(self, key: str) -> list[float]:
        return list(self._ts.get(key, ()))

    def get_json(self, key: str) -> Any:
        item = self._kv.get(key)
        if item is None:
            return None
        value, exp = item
        if exp is not None and exp < self._now:
            del self._kv[key]
            return None
        # values are handed out by reference; callers always write back with set_json
        return value

    def set_json(self, key: str, value: Any, ttl_s: int | None = None) -> None:
        # before the first counter write the store has no clock of its own yet; use the
        # wall clock so values seeded up front (warm-started baselines) do not expire at once
        exp = (self._now or time.time()) + ttl_s if ttl_s else None
        self._kv[key] = (value, exp)

    def ping(self) -> bool:
        return True

    def _gc(self) -> None:
        # drop expired members and old 15-minute HLL slots so long replays stay small
        now = self._now
        self._unique = {k: v for k, v in self._unique.items() if v >= now}
        self._kv = {k: v for k, v in self._kv.items() if v[1] is None or v[1] >= now}
        self._sets = {k: v for k, v in self._sets.items() if v[1] is None or v[1] >= now}
        cutoff = int(now // 900) - 8
        for k in [k for k in self._hll if k.rsplit(":", 1)[-1].isdigit()
                  and int(k.rsplit(":", 1)[-1]) < cutoff]:
            del self._hll[k]
