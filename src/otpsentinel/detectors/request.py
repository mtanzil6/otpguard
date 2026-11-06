"""Layer 1: the request on its own."""
from __future__ import annotations

from ..model import Action, Signal
from .base import Context, Detector


class PurposeCap(Detector):
    """D1. Hard cap on OTPs to one number per purpose."""

    id, layer, name = "D1", "L1", "purpose cap"

    def _key(self, ctx: Context) -> str:
        return f"cap:{ctx.purpose}:{ctx.phone.hash}"

    def evaluate(self, ctx: Context) -> Signal | None:
        rule = ctx.policy.purpose(ctx.purpose)
        k = self._key(ctx)
        c1 = ctx.store.window_sum(k, ctx.ts, 60)
        if c1 >= rule.cap_1h:
            return self.signal(1.0, f"{int(c1)} {ctx.purpose} codes to this number in the last hour",
                               scope=f"phone:{ctx.phone.hash}", force=Action.BLOCK, retry_after=3600)
        c24 = ctx.store.window_sum(k, ctx.ts, 1440)
        if c24 >= rule.cap_24h:
            return self.signal(1.0, f"{int(c24)} {ctx.purpose} codes to this number in 24 hours",
                               scope=f"phone:{ctx.phone.hash}", force=Action.BLOCK, retry_after=6 * 3600)
        return None

    def sent(self, ctx: Context) -> None:
        ctx.store.incr(self._key(ctx), ctx.ts)


class DestinationRisk(Detector):
    """D2. Static risk of the destination country or number range."""

    id, layer, name = "D2", "L1", "destination risk"

    def evaluate(self, ctx: Context) -> Signal | None:
        p = ctx.policy
        if not ctx.phone.e164:
            return self.signal(0.5, "number could not be parsed", scope="country:ZZ")
        rule = p.country(ctx.cc)
        if rule.deny:
            return self.signal(1.0, f"country {ctx.cc} is not allowed", scope=f"country:{ctx.cc}",
                               force=Action.BLOCK, retry_after=86400)
        prefix_risk, match = 0.0, ""
        for pref, risk in p.prefixes.items():
            if ctx.phone.e164.startswith(pref) and len(pref) > len(match):
                prefix_risk, match = risk, pref
        if prefix_risk >= 1.0:
            return self.signal(1.0, f"number range {match} is blocked", scope=f"prefix:{match}",
                               force=Action.BLOCK, retry_after=86400)
        score = max(rule.risk, prefix_risk)
        if score <= 0:
            return None
        what = f"number range {match}" if prefix_risk > rule.risk else f"country {ctx.cc}"
        return self.signal(score, f"{what} has risk {score:.2f} in the policy", scope=f"country:{ctx.cc}")
