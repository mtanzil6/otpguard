"""Layer 4: money. The last line of defence when nothing else fires."""
from __future__ import annotations

from ..model import Action, Signal
from .base import Context, Detector

_HOUR, _DAY = 60, 1440


class SpendBudget(Detector):
    """D12. Spend per country and in total, per hour and per day.

    Each budget has a soft level (challenge above it) and a hard level
    (``block_factor`` × budget, block above it). The hard levels are taken atomically
    with ``Store.reserve`` so concurrent requests cannot overspend; the soft level is
    read from the sums the reservation returns."""

    id, layer, name = "D12", "L4", "spend budget"

    def evaluate(self, ctx: Context) -> Signal | None:
        p = ctx.policy
        rule = p.country(ctx.cc)
        price = float(rule.price)
        if price <= 0:
            return None
        bf = float(self.cfg["block_factor"])
        scopes = [(f"spend:{ctx.cc}", f"{ctx.cc} spend", rule.budget_per_hour, rule.budget_per_day),
                  ("spend:all", "total spend", p.budget_per_hour, p.budget_per_day)]
        reserved: list[str] = []
        worst: Signal | None = None
        for key, label, per_hour, per_day in scopes:
            windows = [(w, float(b) * bf) for w, b in ((_HOUR, per_hour), (_DAY, per_day)) if b]
            if not windows:
                continue
            ok, sums = ctx.store.reserve(key, ctx.ts, windows, price)
            if not ok:
                for k in reserved:                      # give back what we took so far
                    ctx.store.incr(k, ctx.ts, -price)
                w, limit, s = next((w, b, s) for (w, b), s in zip(windows, sums) if s + price > b)
                per = "hourly" if w == _HOUR else "daily"
                return self.signal(1.0, f"{label} {s:.2f} is far over the {per} budget {limit / bf:.2f}",
                                   scope=f"country:{ctx.cc}" if key != "spend:all" else "budget:all",
                                   force=Action.BLOCK, retry_after=3600 if w == _HOUR else 6 * 3600)
            reserved.append(key)
            for (w, limit), s in zip(windows, sums):
                if s + price > limit / bf and worst is None:
                    per = "hourly" if w == _HOUR else "daily"
                    worst = self.signal(0.6, f"{label} {s:.2f} is over the {per} budget {limit / bf:.2f}",
                                        scope=f"country:{ctx.cc}" if key != "spend:all" else "budget:all",
                                        force=Action.CHALLENGE, retry_after=600)
        ctx.notes["D12_reserved"] = (reserved, price)
        return worst

    def not_sent(self, ctx: Context) -> None:
        keys, price = ctx.notes.pop("D12_reserved", ([], 0.0))
        for k in keys:
            ctx.store.incr(k, ctx.ts, -price)
