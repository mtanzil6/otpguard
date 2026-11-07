"""Detectors that need history or baselines, the atomic reservations, and the
baseline estimator. State is built by hand so each test is a few lines."""
from __future__ import annotations

import os
import random
import threading

import pytest

from otpguard import Action, OtpRequest, Policy, Sentinel
from otpguard.baselines import Baselines, hour_of_week
from otpguard.store.base import hour
from otpguard.store.memory import MemoryStore
from otpguard.store.redis_store import RedisStore

T0 = 1_767_600_000.0  # a Monday, 08:00 UTC
WEEK = 7 * 86400


def sentinel(store=None, **policy):
    p = Policy.from_dict({"mode": "enforce", "purposes": {"default": {"cap_1h": 10 ** 6, "cap_24h": 10 ** 6}},
                          **policy})
    return Sentinel(p, store or MemoryStore())


def teach(g: Sentinel, dim: str, key: str, value: float, weeks: int = 3, at: float = T0, **kw):
    """Give a baseline ``weeks`` of history at the same hour of the week, or, for keys
    without a weekly profile, the last 24 consecutive hours."""
    if kw.get("by_hour_of_week") is False:
        for h in range(24, 0, -1):
            g.baselines.update(dim, key, hour(at) - h, value, **kw)
        return
    for w in range(weeks, 0, -1):
        for h in range(-2, 3):          # a few hours around it so n >= 12
            g.baselines.update(dim, key, hour(at - w * WEEK) + h, value, **kw)


# --- D4 verification ratio ---------------------------------------------------------------
def test_d4_fires_when_codes_stop_being_entered():
    g = sentinel(detectors={"D4": {"weight": 1.0, "min_sent": 20}})
    g.policy.verification_feedback = True
    # 30 login codes to OM, all verified: quiet
    for i in range(30):
        d = g.check(OtpRequest(f"+9689{i:07d}", "login", timestamp=T0 + i * 10))
        g.report_verified(d.request_id, T0 + i * 10 + 5)
    assert not any(s.detector == "D4" for s in d.reasons)
    # two hours later, 40 more over 20 minutes, none verified. D4 ignores the last five
    # minutes of sends (codes may not be typed yet), so look ten minutes after the last
    t = T0 + 7200
    for i in range(40):
        g.check(OtpRequest(f"+9689{100 + i:07d}", "login", timestamp=t + i * 30))
    d = g.check(OtpRequest("+96891999999", "login", timestamp=t + 40 * 30 + 600))
    assert any(s.detector == "D4" for s in d.reasons)


# --- D5 country share --------------------------------------------------------------------
def test_d5_needs_a_baseline_and_a_real_shift():
    g = sentinel(detectors={"D5": {"weight": 1.0, "min_count": 10}})
    # no baseline yet: Oman at 100 % of traffic says nothing
    for i in range(20):
        d = g.check(OtpRequest(f"+9689{i:07d}", "login", timestamp=T0 + i))
    assert not any(s.detector == "D5" for s in d.reasons)
    teach(g, "share", "OM", 0.015)
    # 80 % Saudi, 20 % Oman over an hour: 13x the usual share
    t = T0 + 3600
    for i in range(200):
        cc = "+9665" if i % 5 else "+9689"
        d = g.check(OtpRequest(f"{cc}{i:08d}"[:13], "login", timestamp=t + i * 15))
    d = g.check(OtpRequest("+96891234567", "login", timestamp=t + 3100))
    assert any(s.detector == "D5" for s in d.reasons)
    # the same share with tiny counts does not pass the Poisson tail
    g2 = sentinel(detectors={"D5": {"weight": 1.0, "min_count": 2, "p_value": 1e-6}})
    teach(g2, "share", "OM", 0.015)
    for i in range(8):
        d = g2.check(OtpRequest(f"+9665{i:08d}", "login", timestamp=t + i))
    for i in range(2):
        d = g2.check(OtpRequest(f"+9689{i:07d}", "login", timestamp=t + 10 + i))
    assert not any(s.detector == "D5" for s in d.reasons)


# --- D6 prefix burst ---------------------------------------------------------------------
def test_d6_new_numbers_in_one_range():
    g = sentinel(home_countries=["SA"], detectors={"D6": {"weight": 1.0, "min_new": 8}})
    # Nigerian range never seen before: cold rate applies
    for i in range(12):
        d = g.check(OtpRequest(f"+23480310{i:05d}", "register", timestamp=T0 + i * 30))
    assert any(s.detector == "D6" for s in d.reasons)
    # a home range with a learned rate of 50 new numbers an hour: 12 in 30 min is normal
    g2 = sentinel(home_countries=["SA"], detectors={"D6": {"weight": 1.0, "min_new": 8}})
    teach(g2, "pnew", "+966512", 50.0, by_hour_of_week=False)
    for i in range(12):
        d = g2.check(OtpRequest(f"+966512{i:06d}", "register", timestamp=T0 + i * 30))
    assert not any(s.detector == "D6" for s in d.reasons)


# --- D7 pacing, per country --------------------------------------------------------------
def test_d7_country_series_catches_paced_pumping_hidden_in_home_traffic():
    rng = random.Random(1)
    g = sentinel(detectors={"D7": {"weight": 1.0, "last_n": 40}})
    t = T0
    # busy, Poisson-like Saudi login traffic with a metronome into Oman underneath it
    next_om = t
    for _ in range(600):
        t += rng.expovariate(1 / 4)
        g.check(OtpRequest(f"+9665{rng.randrange(10 ** 8):08d}", "login", timestamp=t))
        while next_om <= t:
            next_om += 20
            d = g.check(OtpRequest(f"+9689{rng.randrange(10 ** 7):07d}", "login", timestamp=next_om))
    s = [s for s in d.reasons if s.detector == "D7"]
    assert s and "to OM" in s[0].detail


# --- D9 IP rotation ----------------------------------------------------------------------
def test_d9_fresh_ips_above_baseline():
    g = sentinel(detectors={"D9": {"weight": 1.0, "min_count": 20}})
    teach(g, "newip", "OM:register", 0.1, by_hour_of_week=False)
    for i in range(40):
        d = g.check(OtpRequest(f"+9689{i:07d}", "register", timestamp=T0 + i * 10,
                               ip=f"41.{i // 250}.{i % 250}.{1 + i % 200}"))
    assert any(s.detector == "D9" for s in d.reasons)


# --- D11 conversion mismatch -------------------------------------------------------------
def test_d11_resets_without_logins():
    g = sentinel(detectors={"D11": {"weight": 1.0, "min_count": 20, "events": {"reset_password": ["login"]}}})
    teach(g, "conv", "reset_password", 1.0)     # usually one reset per login event
    for i in range(60):
        d = g.check(OtpRequest(f"+9665{i:08d}", "reset_password", timestamp=T0 + i * 20))
    assert any(s.detector == "D11" for s in d.reasons)
    g2 = sentinel(detectors={"D11": {"weight": 1.0, "min_count": 20, "events": {"reset_password": ["login"]}}})
    teach(g2, "conv", "reset_password", 1.0)
    for i in range(60):
        g2.report_event("login", T0 + i * 20, phone=f"+9665{i:08d}")
        d = g2.check(OtpRequest(f"+9665{i:08d}", "reset_password", timestamp=T0 + i * 20 + 1))
    assert not any(s.detector == "D11" for s in d.reasons)


# --- D12 budgets -------------------------------------------------------------------------
def test_d12_daily_and_total_budgets():
    g = sentinel(countries={"OM": {"price": 1.0, "budget_per_hour": 100, "budget_per_day": 3}},
                 detectors={"D12": {"block_factor": 1.0}})
    acts = [g.check(OtpRequest(f"+9689{i:07d}", "login", timestamp=T0 + i * 3600)).action for i in range(5)]
    assert acts == [Action.ALLOW] * 3 + [Action.BLOCK] * 2
    g = sentinel(countries={"default": {"price": 1.0}}, budget={"per_hour": 2},
                 detectors={"D12": {"block_factor": 1.0}})
    acts = [g.check(OtpRequest(f"+9665{i:08d}", "login", timestamp=T0 + i)).action for i in range(4)]
    assert acts == [Action.ALLOW, Action.ALLOW, Action.BLOCK, Action.BLOCK]


def test_blocked_request_gives_its_reservations_back():
    g = sentinel(countries={"OM": {"deny": True, "price": 1.0, "budget_per_hour": 10}},
                 purposes={"login": {"cap_1h": 2, "cap_24h": 2}})
    for i in range(5):
        assert g.check(OtpRequest("+96891234567", "login", timestamp=T0 + i)).action is Action.BLOCK
    assert g.store.window_sum("cap:login:" + g.phones.parse("+96891234567").hash, T0 + 10, 60) == 0
    assert g.store.window_sum("spend:OM", T0 + 10, 60) == 0


# --- atomic reserve ----------------------------------------------------------------------
def stores():
    out = [MemoryStore()]
    try:
        import fakeredis
        out.append(RedisStore(client=fakeredis.FakeRedis()))
    except ImportError:
        pass
    try:
        import redis
        url = os.environ.get("OTPGUARD_TEST_REDIS")    # e.g. redis://localhost:6379/15
        if not url:
            raise RuntimeError("no real Redis configured")
        c = redis.Redis.from_url(url, socket_connect_timeout=0.2)
        c.ping()
        c.flushdb()
        out.append(RedisStore(client=c, prefix="t:"))
    except Exception:
        pass
    return out


@pytest.mark.parametrize("s", stores(), ids=lambda s: type(s).__name__)
def test_reserve_never_exceeds_the_cap_under_concurrency(s):
    cap, threads, each = 5, 8, 20
    ok = []
    lock = threading.Lock()

    def worker():
        for _ in range(each):
            r, _ = s.reserve("race", T0, [(60, cap), (1440, 50)])
            with lock:
                ok.append(r)

    ts = [threading.Thread(target=worker) for _ in range(threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sum(ok) == cap
    assert s.window_sum("race", T0, 60) == cap


# --- baselines ---------------------------------------------------------------------------
def test_hour_of_week_and_weekly_profile():
    assert hour_of_week(hour(T0)) == 8        # Monday 08:00
    assert hour_of_week(hour(T0 + WEEK)) == 8
    b = Baselines(MemoryStore(), alpha=0.1)
    h = hour(T0)
    for w in range(1, 5):                     # four Mondays at 08:00 with value 10, other hours 1
        b.update("x", "k", h - w * 168, 10.0)
        b.update("x", "k", h - w * 168 + 1, 1.0)
    e = b.get("x", "k", h)
    assert e is not None and e.weekly and 7 < e.mean <= 10
    e2 = b.get("x", "k", h + 1)
    assert e2 is not None and e2.weekly and e2.mean < 2
    # an hour of the week with no profile falls back to the overall estimate
    e3 = b.get("x", "k", h + 5)
    assert e3 is not None and not e3.weekly


def test_limiter_hard_ip_cap():
    g = sentinel(detectors={"D8": {"hard_cap": True, "per_ip": 3, "window_min": 10}})
    acts = [g.check(OtpRequest(f"+9665{i:08d}", "login", timestamp=T0 + i, ip="203.0.113.7")).action
            for i in range(5)]
    assert acts == [Action.ALLOW] * 3 + [Action.BLOCK] * 2


def test_memory_store_values_set_before_first_counter_survive():
    s = MemoryStore()
    s.set_json("k", {"a": 1}, ttl_s=3600)
    s.incr("c", T0)
    assert s.get_json("k") == {"a": 1}
