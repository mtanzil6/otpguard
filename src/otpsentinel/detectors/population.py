"""Layer 3: whole populations of traffic. Most of these don't need the client IP."""
from __future__ import annotations

import math
import statistics

from ..model import Signal
from .base import Context, Detector, clamp


def poisson_sf(k: int, lam: float) -> float:
    """P(X >= k) for X ~ Poisson(lam)."""
    if k <= 0:
        return 1.0
    if lam <= 0:
        return 0.0
    if k > lam:
        return _upper_tail(k, lam)
    log_term, cdf = -lam, math.exp(-lam)
    for i in range(1, k):
        log_term += math.log(lam) - math.log(i)
        cdf += math.exp(log_term)
    return max(0.0, 1.0 - cdf)


def _upper_tail(k: int, lam: float) -> float:
    log_term = -lam + k * math.log(lam) - math.lgamma(k + 1)
    total, i = 0.0, k
    while True:
        t = math.exp(log_term)
        total += t
        if t < total * 1e-12 or i > k + 10_000:
            return total
        i += 1
        log_term += math.log(lam) - math.log(i)


def campaign_factor(ctx: Context) -> float:
    return 0.5 if ctx.in_campaign else 1.0


class CountryShare(Detector):
    """D5. A country's share of all OTPs against its usual share for this hour of the week."""

    id, layer, name = "D5", "L3", "country share shift"

    def evaluate(self, ctx: Context) -> Signal | None:
        if ctx.cc in ctx.policy.home_countries or ctx.cc == "ZZ":
            return None
        c = self.cfg
        w = int(c["window_min"])
        n = ctx.store.window_sum(f"otp:cc:{ctx.cc}", ctx.ts, w)
        if n < c["min_count"]:
            return None
        total = ctx.store.window_sum("otp:all", ctx.ts, w)
        if total <= 0:
            return None
        share = n / total
        base = ctx.baselines.get("share", ctx.cc, ctx.hour_index)
        if base is None or base.n < 12:
            return None
        b = max(base.mean, 0.002)
        ratio = share / b
        if ratio < c["ratio_low"] or share - b < c["min_abs"]:
            return None
        score = 0.3 + 0.7 * (ratio - c["ratio_low"]) / (c["ratio_high"] - c["ratio_low"])
        return self.signal(score * campaign_factor(ctx),
                           f"{ctx.cc} is {share:.1%} of OTPs in the last {w} min (usually {b:.1%})",
                           scope=f"country:{ctx.cc}")


class PrefixBurst(Detector):
    """D6. Many never-seen numbers in one number range."""

    id, layer, name = "D6", "L3", "prefix burst"

    def record(self, ctx: Context) -> None:
        if ctx.is_new_number and ctx.phone.e164:
            ctx.store.incr(f"pnew:{ctx.phone.prefix}", ctx.ts)

    def evaluate(self, ctx: Context) -> Signal | None:
        if not (ctx.is_new_number and ctx.phone.e164):
            return None
        c = self.cfg
        n = int(ctx.store.window_sum(f"pnew:{ctx.phone.prefix}", ctx.ts, 30))
        if n < c["min_new"]:
            return None
        base = ctx.baselines.get("pnew", ctx.phone.prefix, ctx.hour_index)
        if base is None:
            # a range we have never sent to; home ranges build a baseline within the hour
            if ctx.cc in ctx.policy.home_countries:
                return None
            rate = float(c["cold_rate_per_hour"])
        else:
            rate = max(base.mean, 0.25)
        lam = rate * 0.5    # expected new numbers in 30 minutes
        p = poisson_sf(n, lam)
        if p >= c["p_value"]:
            return None
        lp = -math.log10(max(p, 1e-300))
        score = 0.4 + (lp + math.log10(c["p_value"])) / 8
        return self.signal(score * campaign_factor(ctx),
                           f"{n} new numbers in {ctx.phone.prefix}… in 30 min (expected {lam:.1f})",
                           scope=f"prefix:{ctx.phone.prefix}")


class Pacing(Detector):
    """D7. Requests for one purpose arriving at a machine-like steady pace."""

    id, layer, name = "D7", "L3", "pacing regularity"

    def record(self, ctx: Context) -> None:
        ctx.store.push_ts(f"ts:{ctx.purpose}", ctx.ts, int(self.cfg["last_n"]), 3600)

    def evaluate(self, ctx: Context) -> Signal | None:
        c = self.cfg
        times = sorted(ctx.store.get_ts(f"ts:{ctx.purpose}"))
        if len(times) < max(10, int(c["last_n"]) // 2):
            return None
        span = times[-1] - times[0]
        if span <= 0:
            return None
        gaps = [b - a for a, b in zip(times, times[1:])]
        mean = statistics.fmean(gaps)
        if mean <= 0:
            return None
        cv = statistics.pstdev(gaps) / mean
        rate_h = (len(times) - 1) / span * 3600
        base = ctx.baselines.get("prate", ctx.purpose, ctx.hour_index)
        expected = max(base.mean if base else 0.0, 5.0)
        if cv > c["max_cv"] or rate_h < c["min_rate_ratio"] * expected:
            return None
        score = 0.5 + 0.5 * (c["max_cv"] - cv) / c["max_cv"]
        return self.signal(score * campaign_factor(ctx),
                           f"{ctx.purpose} requests every {mean:.1f}s with little variation "
                           f"(cv {cv:.2f}, {rate_h:.0f}/h vs ~{expected:.0f}/h)",
                           scope=f"purpose:{ctx.purpose}")


class NetworkConcentration(Detector):
    """D8. Too many requests from one IP, network block or ASN."""

    id, layer, name = "D8", "L3", "network concentration"
    needs_ip = True

    def record(self, ctx: Context) -> None:
        n = ctx.net
        ctx.store.incr(f"ip:{n.ip}", ctx.ts)
        ctx.store.incr(f"net:{n.net}", ctx.ts)
        if n.asn:
            ctx.store.incr(f"asn:{n.asn}", ctx.ts)

    def evaluate(self, ctx: Context) -> Signal | None:
        c, n = self.cfg, ctx.net
        w = int(c["window_min"])
        best, why = 0.0, ""
        for label, key, limit in (("IP", f"ip:{n.ip}", c["per_ip"]),
                                  ("network", f"net:{n.net}", c["per_net"]),
                                  ("ASN", f"asn:{n.asn}" if n.asn else None, c["per_asn"])):
            if key is None:
                continue
            cnt = ctx.store.window_sum(key, ctx.ts, w)
            if cnt > limit:
                s = clamp(0.4 + (cnt - limit) / limit)
                if s > best:
                    best, why = s, f"{int(cnt)} requests from this {label} in {w} min"
        if n.hosting:
            if c["hosting_score"] > best:
                why = "request comes from a hosting or cloud network"
            best = max(best, float(c["hosting_score"]))
        if best <= 0:
            return None
        return self.signal(best, why, scope=f"net:{n.net}")


class IpRotation(Detector):
    """D9. Requests into one country/purpose bucket coming from far more fresh addresses
    than usual."""

    id, layer, name = "D9", "L3", "IP rotation"
    needs_ip = True

    def record(self, ctx: Context) -> None:
        slot = int(ctx.ts // 900)
        b = f"{ctx.cc}:{ctx.purpose}"
        ctx.store.incr(f"rot:n:{b}", ctx.ts)
        ctx.store.hll_add(f"rot:ips:{b}:{slot}", ctx.net.ip, 1800)
        if ctx.is_new_ip:
            ctx.store.incr(f"rot:new:{b}", ctx.ts)

    def evaluate(self, ctx: Context) -> Signal | None:
        c = self.cfg
        b = f"{ctx.cc}:{ctx.purpose}"
        n = ctx.store.window_sum(f"rot:n:{b}", ctx.ts, 15)
        if n < c["min_count"]:
            return None
        new_ratio = ctx.store.window_sum(f"rot:new:{b}", ctx.ts, 15) / n
        base = ctx.baselines.get("newip", b, ctx.hour_index)
        if base is None or base.n < 12:
            return None
        lift = new_ratio - base.mean
        if lift < c["new_ip_lift"]:
            return None
        slot = int(ctx.ts // 900)
        distinct = ctx.store.hll_count(f"rot:ips:{b}:{slot}")
        slot_n = ctx.store.window_sum(f"rot:n:{b}", ctx.ts, int((ctx.ts % 900) // 60) + 1)
        if slot_n >= 10 and distinct / slot_n < c["distinct_ratio"]:
            return None
        score = 0.4 + 0.6 * lift / max(1 - base.mean, 1e-6)
        return self.signal(score, f"{new_ratio:.0%} of {int(n)} {ctx.purpose} requests to {ctx.cc} in 15 min "
                                  f"from never-seen IPs (usually {base.mean:.0%})", scope=f"country:{ctx.cc}")


class ClientIntegrity(Detector):
    """D10. Session token and device checks."""

    id, layer, name = "D10", "L3", "client integrity"

    def evaluate(self, ctx: Context) -> Signal | None:
        c, r = self.cfg, ctx.req
        if r.attestation == "failed":
            return self.signal(0.9, "device attestation failed", scope="client")
        if r.session_id is None:
            if c["require_session"]:
                return self.signal(0.6, "no session token", scope="client")
            return None
        if r.session_age_ms is not None and r.session_age_ms < c["min_age_ms"]:
            return self.signal(0.8, f"code requested {r.session_age_ms} ms after the page was issued",
                               scope="client")
        uses = ctx.store.window_sum(f"sess:{r.session_id}", ctx.ts, 60)
        if uses > c["max_reuse"]:
            return self.signal(0.7, f"session token used {int(uses)} times in an hour", scope="client")
        return None

    def record(self, ctx: Context) -> None:
        if ctx.req.session_id:
            ctx.store.incr(f"sess:{ctx.req.session_id}", ctx.ts)


class ConversionMismatch(Detector):
    """D11. OTP volume for a purpose rising while the activity it should lead to does not."""

    id, layer, name = "D11", "L3", "conversion mismatch"
    needs_events = True

    def kinds(self, purpose: str) -> list[str]:
        """Event kinds that should follow this purpose. Only purposes listed in the
        policy are checked; a register surge without orders is normal during a launch."""
        return list(self.cfg.get("events", {}).get(purpose, []))

    def evaluate(self, ctx: Context) -> Signal | None:
        c = self.cfg
        if not self.kinds(ctx.purpose):
            return None
        w = int(c["window_min"])
        otp = ctx.store.window_sum(f"otp:p:{ctx.purpose}", ctx.ts, w)
        if otp < c["min_count"]:
            return None
        ev = sum(ctx.store.window_sum(f"ev:{k}", ctx.ts, w) for k in self.kinds(ctx.purpose))
        base = ctx.baselines.get("conv", ctx.purpose, ctx.hour_index)
        if base is None or base.n < 12:
            return None
        ratio = otp / max(ev, 1.0)
        expected = max(base.mean, 0.1)
        if ratio < c["ratio"] * expected:
            return None
        score = 0.3 + 0.35 * (ratio / (c["ratio"] * expected) - 1)
        return self.signal(score * campaign_factor(ctx),
                           f"{int(otp)} {ctx.purpose} codes vs {int(ev)} follow-up events in {w} min "
                           f"({ratio:.1f} per event, usually {expected:.1f})", scope=f"purpose:{ctx.purpose}")
