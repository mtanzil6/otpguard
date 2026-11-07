"""Audit trail in a SQL database (PostgreSQL, MySQL or SQLite). Needs ``otpguard[sql]``."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from sqlalchemy import (JSON, BigInteger, Column, DateTime, Float, Integer, MetaData, String, Table,
                        Text, create_engine, delete, insert, select, update)

if TYPE_CHECKING:
    from .detectors.base import Context
    from .model import Decision
    from .policy import Policy

metadata = MetaData()

otp_events = Table(
    "otp_events", metadata,
    Column("id", BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True),
    Column("request_id", String(32), unique=True, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, index=True),
    Column("purpose", String(40), nullable=False),
    Column("phone_hash", String(32), nullable=False, index=True),
    Column("country", String(2), nullable=False),
    Column("prefix", String(16)),
    Column("ip_net", String(64)),
    Column("asn", Integer),
    Column("risk", Float, nullable=False),
    Column("action", String(10), nullable=False),
    Column("enforced", Integer, nullable=False),
    Column("reasons", JSON),
    Column("policy_version", String(40)),
    Column("sent_at", DateTime(timezone=True)),
    Column("verified_at", DateTime(timezone=True)),
    Column("cost", Float),
)

policies = Table(
    "policies", metadata,
    Column("version", String(40), primary_key=True),
    Column("mode", String(10), nullable=False),
    Column("yaml", Text, nullable=False),
    Column("activated_at", DateTime(timezone=True), nullable=False),
)

alerts = Table(
    "alerts", metadata,
    Column("id", BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True),
    Column("detector", String(8), nullable=False),
    Column("scope", String(80), nullable=False),
    Column("opened_at", DateTime(timezone=True), nullable=False),
    Column("last_seen_at", DateTime(timezone=True), nullable=False),
    Column("hits", Integer, nullable=False, default=1),
    Column("peak_score", Float, nullable=False),
    Column("example", Text),
)

baselines = Table(
    "baselines", metadata,
    Column("key", String(160), primary_key=True),
    Column("value", JSON, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)


def _dt(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


class SqlAudit:
    def __init__(self, url: str, alert_score: float = 0.7, alert_gap_s: int = 1800,
                 create: bool = True):
        self.engine = create_engine(url, future=True, pool_pre_ping=True)
        if create:
            metadata.create_all(self.engine)
        self.alert_score = alert_score
        self.alert_gap_s = alert_gap_s
        self._open: dict[tuple[str, str], tuple[int, float]] = {}

    def save_policy(self, policy: "Policy", yaml_text: str) -> None:
        with self.engine.begin() as c:
            exists = c.execute(select(policies.c.version).where(policies.c.version == policy.version)).first()
            if not exists:
                c.execute(insert(policies).values(version=policy.version, mode=policy.mode,
                                                  yaml=yaml_text, activated_at=_dt(time.time())))

    def record(self, d: "Decision", ctx: "Context") -> None:
        row: dict[str, Any] = dict(
            request_id=d.request_id, created_at=_dt(ctx.ts), purpose=ctx.purpose,
            phone_hash=ctx.phone.hash, country=ctx.phone.region, prefix=ctx.phone.prefix,
            ip_net=ctx.net.net if ctx.net else None, asn=ctx.net.asn if ctx.net else None,
            risk=d.risk, action=d.action.value, enforced=int(d.enforced),
            reasons=[{"detector": s.detector, "score": round(s.score, 3), "detail": s.detail}
                     for s in d.reasons],
            policy_version=d.policy_version,
            sent_at=_dt(ctx.ts) if d.allowed else None,
        )
        with self.engine.begin() as c:
            c.execute(insert(otp_events).values(**row))
            for s in d.reasons:
                if s.score >= self.alert_score and s.scope:
                    self._alert(c, s.detector, s.scope, s.score, s.detail, ctx.ts)

    def _alert(self, c, detector: str, scope: str, score: float, detail: str, ts: float) -> None:
        key = (detector, scope)
        cur = self._open.get(key)
        if cur and ts - cur[1] <= self.alert_gap_s:
            aid = cur[0]
            c.execute(update(alerts).where(alerts.c.id == aid).values(
                last_seen_at=_dt(ts), hits=alerts.c.hits + 1))
            row = c.execute(select(alerts.c.peak_score).where(alerts.c.id == aid)).first()
            if row and score > row[0]:
                c.execute(update(alerts).where(alerts.c.id == aid).values(peak_score=score, example=detail))
            self._open[key] = (aid, ts)
            return
        res = c.execute(insert(alerts).values(detector=detector, scope=scope, opened_at=_dt(ts),
                                              last_seen_at=_dt(ts), hits=1, peak_score=score,
                                              example=detail))
        self._open[key] = (res.inserted_primary_key[0], ts)

    def mark_sent(self, request_id: str, cost: float) -> None:
        with self.engine.begin() as c:
            c.execute(update(otp_events).where(otp_events.c.request_id == request_id).values(cost=cost))

    def mark_verified(self, request_id: str, ts: float) -> None:
        with self.engine.begin() as c:
            c.execute(update(otp_events).where(otp_events.c.request_id == request_id)
                      .values(verified_at=_dt(ts)))

    def snapshot_baselines(self, store, keys: list[str]) -> int:
        """Copy baseline records from the live store into SQL (for review or a warm restart)."""
        n = 0
        with self.engine.begin() as c:
            for k in keys:
                v = store.get_json(k)
                if v is None:
                    continue
                c.execute(baselines.delete().where(baselines.c.key == k))
                c.execute(insert(baselines).values(key=k, value=json.loads(json.dumps(v)),
                                                   updated_at=_dt(time.time())))
                n += 1
        return n

    def prune(self, retention_days: int = 90, now: float | None = None) -> dict[str, int]:
        """Delete decisions and closed alerts older than ``retention_days``. Run it from
        cron (``otpguard prune --sql URL --days 90``); large installations may prefer
        to partition ``otp_events`` by day in the database and drop partitions instead."""
        cutoff = _dt((now if now is not None else time.time()) - retention_days * 86400)
        with self.engine.begin() as c:
            ev = c.execute(delete(otp_events).where(otp_events.c.created_at < cutoff)).rowcount
            al = c.execute(delete(alerts).where(alerts.c.last_seen_at < cutoff)).rowcount
        return {"otp_events": int(ev or 0), "alerts": int(al or 0)}
