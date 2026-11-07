"""Hourly baselines (EWMA mean and variance) that the population detectors compare against.

Each key keeps an overall estimate and, once there is enough history, one per hour of
the week. Hours with no traffic count as zeros; for sparse keys such as prefixes the
zeros are applied lazily when the key is next touched."""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from .store.base import Store


def hour_of_week(hour_index: int) -> int:
    # hour_index is hours since the epoch; 1970-01-01 was a Thursday
    return (hour_index + 3 * 24) % 168


@dataclass
class Estimate:
    mean: float
    std: float
    n: int            # hours of history behind the key
    weekly: bool = False


class Baselines:
    def __init__(self, store: Store, alpha: float = 0.05, how_min_samples: int = 3):
        self.store = store
        self.alpha = alpha
        self.how_min = how_min_samples

    def _key(self, dim: str, key: str) -> str:
        return f"base:{dim}:{key}"

    def update(self, dim: str, key: str, hour_index: int, value: float, alpha: float | None = None,
               by_hour_of_week: bool = True) -> None:
        a = alpha or self.alpha
        k = self._key(dim, key)
        rec: dict[str, Any] = self.store.get_json(k) or {"m": None, "v": 0.0, "n": 0, "h": None, "w": {}}
        # decay for the hours we did not see (sparse keys)
        if rec["m"] is not None and rec["h"] is not None and hour_index - rec["h"] > 1:
            gap = hour_index - rec["h"] - 1
            f = (1 - a) ** gap
            rec["v"] = rec["v"] * f + (1 - f) * rec["m"] ** 2 * a   # rough: zeros add spread
            rec["m"] *= f
            rec["n"] += gap
        rec["m"], rec["v"] = _ewma(rec["m"], rec["v"], value, a)
        rec["n"] += 1
        rec["h"] = hour_index
        if by_hour_of_week:
            how = str(hour_of_week(hour_index))
            w = rec["w"].get(how) or [None, 0.0, 0]
            # weekly series are short, so they adapt faster
            w[0], w[1] = _ewma(w[0], w[1], value, min(0.5, a * 6))
            w[2] += 1
            rec["w"][how] = w
        self.store.set_json(k, rec, ttl_s=60 * 86400)

    def get(self, dim: str, key: str, hour_index: int) -> Estimate | None:
        rec = self.store.get_json(self._key(dim, key))
        if not rec or rec["m"] is None:
            return None
        w = rec["w"].get(str(hour_of_week(hour_index)))
        if w and w[2] >= self.how_min and w[0] is not None:
            return Estimate(w[0], math.sqrt(max(w[1], 0.0)), rec["n"], weekly=True)
        m, v = rec["m"], rec["v"]
        if rec["h"] is not None and hour_index - rec["h"] > 1:
            f = (1 - self.alpha) ** (hour_index - rec["h"] - 1)
            m *= f
        return Estimate(m, math.sqrt(max(v, 0.0)), rec["n"])


def _ewma(mean: float | None, var: float, x: float, a: float) -> tuple[float, float]:
    if mean is None:
        return x, 0.0
    d = x - mean
    mean = mean + a * d
    var = (1 - a) * (var + a * d * d)
    return mean, var
