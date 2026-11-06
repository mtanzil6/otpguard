"""The main entry point: Sentinel.check() before each OTP, report_* afterwards."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

from . import detectors as D
from .baselines import Baselines
from .detectors.base import Context
from .enrich import AsnTable, NetworkParser, PhoneParser
from .model import Action, Decision, OtpRequest, Signal, new_request_id
from .policy import Policy
from .scoring import combine
from .store.base import Store, StoreError, hour
from .store.memory import MemoryStore

log = logging.getLogger("otpsentinel")

SEEN_TTL = 90 * 86400
REQ_TTL = 2 * 3600


class Sentinel:
    def __init__(self, policy: Policy | None = None, store: Store | None = None,
                 audit: Any = None, asn_table: AsnTable | None = None,
                 hosting_asns: set[int] | None = None):
        self.policy = policy or Policy()
        self.store: Store = store or MemoryStore()
        self.audit = audit                     # optional SqlAudit (or anything with .record())
        self.baselines = Baselines(self.store, alpha=0.05)
        self.phones = PhoneParser(self.policy.secret_bytes(), self.policy.default_region,
                                  self.policy.prefix_digits)
        self.networks = NetworkParser(asn_table, hosting_asns)
        self.detectors = [cls(self.policy) for cls in D.ALL]
        self._d11 = next(d for d in self.detectors if d.id == "D11")
        self._last_hour: int | None = None
        self._fallback = MemoryStore()         # used only when the main store is down
        self.on_decision: Callable[[Decision, Context], None] | None = None

    @classmethod
    def from_config(cls, policy_path: str | Path, redis_url: str | None = None,
                    sql_url: str | None = None, asn_tsv: str | None = None) -> "Sentinel":
        policy = Policy.load(policy_path)
        store: Store | None = None
        if redis_url:
            from .store.redis_store import RedisStore
            store = RedisStore(url=redis_url)
        audit = None
        if sql_url:
            from .sql import SqlAudit
            audit = SqlAudit(sql_url)
            audit.save_policy(policy, Path(policy_path).read_text(encoding="utf-8"))
        asn = AsnTable.load(asn_tsv) if asn_tsv else None
        return cls(policy, store, audit, asn)

    # ---------------------------------------------------------------------------------
    def check(self, req: OtpRequest) -> Decision:
        try:
            return self._check(req, self.store)
        except StoreError as e:
            log.warning("store unavailable, falling back (%s): %s", self.policy.fail_mode, e)
            return self._fail(req, e)

    def _check(self, req: OtpRequest, store: Store) -> Decision:
        p = self.policy
        ts = req.ts()
        rid = req.request_id or new_request_id()
        phone = self.phones.parse(req.phone)
        net = self.networks.parse(req.ip)
        bl = self.baselines if store is self.store else Baselines(store)
        self._maybe_roll(ts, store, bl)
        ctx = Context(req=req, ts=ts, hour_index=hour(ts), phone=phone, net=net, policy=p,
                      store=store, baselines=bl, in_campaign=p.in_campaign(ts))
        ctx.is_new_number = store.add_unique("seen", phone.hash, ts, SEEN_TTL)
        if net is not None:
            ctx.is_new_ip = store.add_unique("seenip", net.ip, ts, 30 * 86400)
        self._count_attempt(ctx)

        active = [d for d in self.detectors if d.active(ctx)]
        for d in active:
            d.record(ctx)
        signals: list[Signal] = []
        for d in active:
            s = d.evaluate(ctx)
            if s is not None and (s.score > 0 or s.force is not None):
                signals.append(s)

        risk, action, ordered, retry = combine(signals, p, req.purpose, req.challenge_passed)
        decision = Decision(request_id=rid, action=action, risk=risk, reasons=ordered,
                            enforced=p.enforce, policy_version=p.version, retry_after=retry,
                            phone_hash=phone.hash, country=phone.region)
        if decision.allowed:
            for d in active:
                d.sent(ctx)
        store.set_json(f"req:{rid}", {"h": phone.hash, "cc": phone.region, "p": req.purpose,
                                      "ts": ts}, ttl_s=REQ_TTL)
        if self.audit is not None:
            try:
                self.audit.record(decision, ctx)
            except Exception as e:  # auditing must never break sign-in
                log.warning("audit write failed: %s", e)
        if self.on_decision is not None:
            self.on_decision(decision, ctx)
        return decision

    def _fail(self, req: OtpRequest, err: Exception) -> Decision:
        if self.policy.fail_mode == "closed":
            return Decision(request_id=req.request_id or new_request_id(), action=Action.BLOCK,
                            risk=1.0, reasons=[Signal("store", 1.0, "protection store unavailable")],
                            enforced=True, policy_version=self.policy.version, retry_after=60)
        # open: keep simple per-process limits so an outage isn't a free-for-all
        return self._check(req, self._fallback)

    # feedback ------------------------------------------------------------------------
    def report_sent(self, request_id: str, cost: float | None = None) -> None:
        if self.audit is not None and cost is not None:
            self.audit.mark_sent(request_id, cost)

    def report_verified(self, request_id: str, ts: float | None = None) -> bool:
        rec = self.store.get_json(f"req:{request_id}")
        if not rec:
            return False
        t = ts if ts is not None else rec["ts"] + 1
        self.store.incr(f"ver:{rec['h']}", t)
        self.store.incr(f"ver:p:{rec['p']}:cc:{rec['cc']}", t)
        if self.audit is not None:
            self.audit.mark_verified(request_id, t)
        return True

    def report_event(self, kind: str, ts: float, phone: str | None = None) -> None:
        """Downstream activity (a login, an order) for the conversion detector."""
        self.store.incr(f"ev:{kind}", ts)
        self.store.incr("ev:any", ts)

    # internals -----------------------------------------------------------------------
    def _count_attempt(self, ctx: Context) -> None:
        s, ts = ctx.store, ctx.ts
        s.incr("otp:all", ts)
        s.incr(f"otp:cc:{ctx.cc}", ts)
        s.incr(f"otp:p:{ctx.purpose}", ts)
        self._remember(s, "known:cc", ctx.cc, ts)
        self._remember(s, "known:purpose", ctx.purpose, ts)
        if ctx.is_new_number and ctx.phone.e164:
            s.incr(f"pnewc:{ctx.phone.prefix}", ts)
            self._remember(s, f"act:pfx:{ctx.hour_index}", ctx.phone.prefix, ts, ttl=4 * 3600)
        self._remember(s, f"act:pcc:{ctx.hour_index}", f"{ctx.purpose}:cc:{ctx.cc}", ts, ttl=4 * 3600)
        if ctx.net is not None:
            self._remember(s, f"act:rot:{ctx.hour_index}", f"{ctx.cc}:{ctx.purpose}", ts, ttl=4 * 3600)

    @staticmethod
    def _remember(s: Store, list_key: str, item: str, ts: float, ttl: int = 60 * 86400) -> None:
        if s.add_unique(list_key, item, ts, ttl):
            items = s.get_json(list_key) or []
            items.append(item)
            s.set_json(list_key, items, ttl_s=ttl)

    def _maybe_roll(self, ts: float, store: Store, bl: Baselines) -> None:
        h = hour(ts)
        if self._last_hour is None:
            self._last_hour = h
            return
        if h <= self._last_hour:
            return
        for hh in range(max(self._last_hour, h - 3), h):
            # only one server updates a given hour
            if store.add_unique("rolled", str(hh), ts, 7 * 86400):
                self._update_baselines(hh, store, bl)
        self._last_hour = h

    def _update_baselines(self, hh: int, s: Store, bl: Baselines) -> None:
        # Baselines keep learning during campaigns. Freezing them made every planned
        # sale look like an attack; instead the volume detectors are damped (see
        # detectors.population.campaign_factor).
        end = (hh + 1) * 3600 - 1
        total = s.window_sum("otp:all", end, 60)
        if total >= 20:
            for cc in s.get_json("known:cc") or []:
                bl.update("share", cc, hh, s.window_sum(f"otp:cc:{cc}", end, 60) / total)
        ev_any = s.window_sum("ev:any", end, 60)
        for p in s.get_json("known:purpose") or []:
            n = s.window_sum(f"otp:p:{p}", end, 60)
            bl.update("prate", p, hh, n)
            kinds = self._d11.kinds(p)
            if self.policy.event_feedback and kinds and (n >= 5 or ev_any > 0):
                ev = sum(s.window_sum(f"ev:{k}", end, 60) for k in kinds)
                bl.update("conv", p, hh, n / max(ev, 1.0))
        for pfx in s.get_json(f"act:pfx:{hh}") or []:
            bl.update("pnew", pfx, hh, s.window_sum(f"pnewc:{pfx}", end, 60), by_hour_of_week=False)
        for b in s.get_json(f"act:rot:{hh}") or []:
            n = s.window_sum(f"rot:n:{b}", end, 60)
            if n >= 10:
                bl.update("newip", b, hh, s.window_sum(f"rot:new:{b}", end, 60) / n, by_hour_of_week=False)
        if self.policy.verification_feedback:
            for key in s.get_json(f"act:pcc:{hh}") or []:
                sent = s.window_sum(f"snd:p:{key}", end, 60)
                if sent >= 10:
                    ver = s.window_sum(f"ver:p:{key}", end, 60)
                    bl.update("vr", key, hh, min(1.0, ver / sent), by_hour_of_week=False)
