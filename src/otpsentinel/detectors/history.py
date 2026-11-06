"""Layer 2: what happened to earlier codes for the same number or country."""
from __future__ import annotations

from ..model import Signal
from .base import Context, Detector, clamp


class ResendWithoutVerify(Detector):
    """D3. Several codes to the same number and none of them entered."""

    id, layer, name = "D3", "L2", "resend without verify"
    needs_verification = True

    def evaluate(self, ctx: Context) -> Signal | None:
        w, k = int(self.cfg["window_min"]), int(self.cfg["k"])
        h = ctx.phone.hash
        sends = ctx.store.window_sum(f"snd:{h}", ctx.ts, w)
        if sends < k:
            return None
        if ctx.store.window_sum(f"ver:{h}", ctx.ts, w) > 0:
            return None
        return self.signal(clamp((sends - k + 1) / k + 0.3),
                           f"{int(sends)} codes to this number in {w} min, none entered",
                           scope=f"phone:{h}")

    def sent(self, ctx: Context) -> None:
        ctx.store.incr(f"snd:{ctx.phone.hash}", ctx.ts)


class VerificationRatio(Detector):
    """D4. Share of codes that get entered, per country and purpose."""

    id, layer, name = "D4", "L2", "verification ratio"
    needs_verification = True
    LAG_S = 300   # codes sent in the last few minutes may not be typed in yet

    def evaluate(self, ctx: Context) -> Signal | None:
        c = self.cfg
        w = int(c["window_min"])
        key = f"{ctx.purpose}:cc:{ctx.cc}"
        sent = ctx.store.window_sum(f"snd:p:{key}", ctx.ts - self.LAG_S, max(1, w - 5))
        if sent < c["min_sent"]:
            return None
        ver = ctx.store.window_sum(f"ver:p:{key}", ctx.ts, w)
        base = ctx.baselines.get("vr", key, ctx.hour_index)
        r0 = base.mean if base and base.n >= 6 else float(c["prior_ratio"])
        r0 = max(r0, 0.05)
        k = float(c["prior_strength"])
        mean = (ver + r0 * k) / (sent + k)
        deficit = 1 - mean / r0
        drop = float(c["drop"])
        if deficit <= drop:
            return None
        return self.signal(0.4 + 0.6 * (deficit - drop) / (1 - drop),
                           f"only {ver:.0f} of {sent:.0f} {ctx.purpose} codes to {ctx.cc} entered "
                           f"(usually {r0:.0%})", scope=f"country:{ctx.cc}")

    def sent(self, ctx: Context) -> None:
        ctx.store.incr(f"snd:p:{ctx.purpose}:cc:{ctx.cc}", ctx.ts)
