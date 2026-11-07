from __future__ import annotations

import json
from typing import Any

from .base import StoreError, hour, hours_for, minute

try:
    import redis
except ImportError:  # pragma: no cover - optional dependency
    redis = None


# One script per hard rule: sum every window, and increment only if every cap holds.
# KEYS: minute keys of the window(s) (last one is the current minute), then the hour keys
#       (last one is the current hour)
# ARGV: n_minute_keys, n_windows, then per window (n_keys, limit, uses_hours), then amount,
#       minute ttl, hour ttl
_RESERVE_LUA = """
local nmin = tonumber(ARGV[1])
local nwin = tonumber(ARGV[2])
local a = 3
local amount = tonumber(ARGV[3 + nwin * 3])
local mttl = tonumber(ARGV[4 + nwin * 3])
local httl = tonumber(ARGV[5 + nwin * 3])
local sums = {}
local ok = 1
for w = 1, nwin do
  local nkeys = tonumber(ARGV[a]); local limit = tonumber(ARGV[a + 1]); local hours = tonumber(ARGV[a + 2])
  a = a + 3
  local s = 0
  local last = nmin
  if hours == 1 then last = #KEYS end
  for i = last - nkeys + 1, last do
    local v = redis.call('GET', KEYS[i])
    if v then s = s + tonumber(v) end
  end
  sums[w] = s
  if s + amount > limit then ok = 0 end
end
if ok == 1 then
  redis.call('INCRBYFLOAT', KEYS[nmin], amount); redis.call('EXPIRE', KEYS[nmin], mttl)
  redis.call('INCRBYFLOAT', KEYS[#KEYS], amount); redis.call('EXPIRE', KEYS[#KEYS], httl)
end
local out = {ok}
for w = 1, nwin do out[#out + 1] = tostring(sums[w]) end
return out
"""


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
        self._reserve = client.register_script(_RESERVE_LUA)

    def reserve(self, key: str, ts: float, windows: list[tuple[int, float]],
                amount: float = 1.0) -> tuple[bool, list[float]]:
        m, h = minute(ts), hour(ts)
        max_min = max([w for w, _ in windows if w <= 120] or [1])
        max_hr = max([hours_for(w) for w, _ in windows if w > 120] or [1])
        mkeys = [f"{self.p}m:{key}:{b}" for b in range(m - max_min + 1, m + 1)]
        hkeys = [f"{self.p}h:{key}:{b}" for b in range(h - max_hr + 1, h + 1)]
        argv: list[Any] = [len(mkeys), len(windows)]
        for w, limit in windows:
            if w <= 120:
                argv += [w, limit, 0]
            else:
                argv += [hours_for(w), limit, 1]
        argv += [amount, 3 * 3600, 8 * 86400]
        res = self._call(self._reserve, keys=mkeys + hkeys, args=argv)
        return bool(int(res[0])), [float(x) for x in res[1:]]

    def set_add(self, key: str, member: str, ttl_s: int) -> bool:
        k = f"{self.p}s:{key}"
        pipe = self.r.pipeline(transaction=False)
        pipe.sadd(k, member)
        pipe.expire(k, ttl_s)
        return bool(self._call(pipe.execute)[0])

    def set_members(self, key: str) -> list[str]:
        return [v.decode() if isinstance(v, bytes) else str(v)
                for v in self._call(self.r.smembers, f"{self.p}s:{key}")]

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
