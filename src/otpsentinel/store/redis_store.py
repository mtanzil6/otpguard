from __future__ import annotations

import json
from typing import Any

from .base import StoreError, hour, hours_for, minute

try:
    import redis
except ImportError:  # pragma: no cover - optional dependency
    redis = None


class RedisStore:
    """Redis backend, shared by every app server. Needs ``pip install otpsentinel[redis]``."""

    def __init__(self, client: Any = None, url: str | None = None, prefix: str = "otps:"):
        if client is None:
            if redis is None:
                raise ImportError("RedisStore needs the redis package: pip install otpsentinel[redis]")
            client = redis.Redis.from_url(url or "redis://localhost:6379/0",
                                          socket_timeout=0.25, socket_connect_timeout=0.25)
        self.r = client
        self.p = prefix

    def _call(self, fn, *a, **kw):
        try:
            return fn(*a, **kw)
        except Exception as e:  # connection errors, timeouts
            if redis is not None and isinstance(e, redis.RedisError):
                raise StoreError(str(e)) from e
            raise

    def incr(self, key: str, ts: float, amount: float = 1.0) -> None:
        mk = f"{self.p}m:{key}:{minute(ts)}"
        hk = f"{self.p}h:{key}:{hour(ts)}"
        pipe = self.r.pipeline(transaction=False)
        pipe.incrbyfloat(mk, amount)
        pipe.expire(mk, 3 * 3600)
        pipe.incrbyfloat(hk, amount)
        pipe.expire(hk, 8 * 86400)
        self._call(pipe.execute)

    def window_sum(self, key: str, ts: float, minutes: int) -> float:
        if minutes <= 120:
            m = minute(ts)
            keys = [f"{self.p}m:{key}:{b}" for b in range(m - minutes + 1, m + 1)]
        else:
            h = hour(ts)
            keys = [f"{self.p}h:{key}:{b}" for b in range(h - hours_for(minutes) + 1, h + 1)]
        vals = self._call(self.r.mget, keys)
        return sum(float(v) for v in vals if v is not None)

    def add_unique(self, key: str, member: str, ts: float, ttl_s: int) -> bool:
        return bool(self._call(self.r.set, f"{self.p}u:{key}:{member}", 1, nx=True, ex=ttl_s))

    def hll_add(self, key: str, member: str, ttl_s: int) -> None:
        k = f"{self.p}x:{key}"
        pipe = self.r.pipeline(transaction=False)
        pipe.pfadd(k, member)
        pipe.expire(k, ttl_s)
        self._call(pipe.execute)

    def hll_count(self, key: str) -> int:
        return int(self._call(self.r.pfcount, f"{self.p}x:{key}"))

    def push_ts(self, key: str, ts: float, maxlen: int, ttl_s: int) -> None:
        k = f"{self.p}t:{key}"
        pipe = self.r.pipeline(transaction=False)
        pipe.rpush(k, ts)
        pipe.ltrim(k, -maxlen, -1)
        pipe.expire(k, ttl_s)
        self._call(pipe.execute)

    def get_ts(self, key: str) -> list[float]:
        return [float(v) for v in self._call(self.r.lrange, f"{self.p}t:{key}", 0, -1)]

    def get_json(self, key: str) -> Any:
        v = self._call(self.r.get, f"{self.p}j:{key}")
        return json.loads(v) if v else None

    def set_json(self, key: str, value: Any, ttl_s: int | None = None) -> None:
        self._call(self.r.set, f"{self.p}j:{key}", json.dumps(value), ex=ttl_s)

    def ping(self) -> bool:
        try:
            return bool(self.r.ping())
        except Exception:
            return False
