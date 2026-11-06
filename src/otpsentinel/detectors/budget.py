"""Layer 4: money. The last line of defence when nothing else fires."""
from __future__ import annotations

from ..model import Action, Signal
from .base import Context, Detector


class SpendBudget(Detector):
    """D12. Hourly spend per country."""

    id, layer, name = "D12", "L4", "spend budget"

    def evaluate(self, ctx: Context) -> Signal | None:
        rule = ctx.policy.country(ctx.cc)
        if not rule.budget_per_hour:
            return None
        budget = float(rule.budget_per_hour)
        spent = ctx.store.window_sum(f"spend:{ctx.cc}", ctx.ts, 60)
        after = spent + rule.price
        if after > budget * float(self.cfg["block_factor"]):
            return self.signal(1.0, f"{ctx.cc} spend {spent:.2f} is far over the hourly budget {budget:.2f}",
                               scope=f"country:{ctx.cc}", force=Action.BLOCK, retry_after=3600)
        if after > budget:
            return self.signal(0.6, f"{ctx.cc} spend {spent:.2f} is over the hourly budget {budget:.2f}",
                               scope=f"country:{ctx.cc}", force=Action.CHALLENGE, retry_after=600)
        return None

    def sent(self, ctx: Context) -> None:
        price = ctx.policy.country(ctx.cc).price
        if price:
            ctx.store.incr(f"spend:{ctx.cc}", ctx.ts, price)
