import pytest

from otpsentinel import OtpRequest, Policy, Sentinel
from otpsentinel import simulate as sim
from otpsentinel.policy import _ts
from otpsentinel.replay import Mapping, replay
from otpsentinel.store.memory import MemoryStore

T0 = 1_767_600_000.0


def stores():
    out = [MemoryStore()]
    try:
        import fakeredis

        from otpsentinel.store.redis_store import RedisStore
        out.append(RedisStore(client=fakeredis.FakeRedis()))
    except ImportError:
        pass
    return out


@pytest.mark.parametrize("s", stores(), ids=lambda s: type(s).__name__)
def test_store_contract(s):
    for i in range(5):
        s.incr("k", T0 + i * 60)
    assert s.window_sum("k", T0 + 4 * 60, 3) == 3
    assert s.window_sum("k", T0 + 4 * 60, 1440) == 5
    assert s.add_unique("seen", "a", T0, 60) is True
    assert s.add_unique("seen", "a", T0 + 1, 60) is False
    s.hll_add("h", "x", 60)
    s.hll_add("h", "y", 60)
    s.hll_add("h", "x", 60)
    assert s.hll_count("h") == 2
    for i in range(5):
        s.push_ts("t", T0 + i, 3, 60)
    assert s.get_ts("t") == [T0 + 2, T0 + 3, T0 + 4]
    s.set_json("j", {"a": [1, 2]})
    assert s.get_json("j") == {"a": [1, 2]}
    assert s.ping()


def test_sql_audit_records_and_alerts():
    pytest.importorskip("sqlalchemy")
    from sqlalchemy import func, select

    from otpsentinel.sql import SqlAudit, alerts, otp_events
    audit = SqlAudit("sqlite://")
    g = Sentinel(Policy.from_dict({"mode": "enforce", "countries": {"OM": {"deny": True}}}),
                 audit=audit)
    d1 = g.check(OtpRequest("0512345678", "login", timestamp=T0))
    g.check(OtpRequest("0096891234567", "login", timestamp=T0 + 1))
    g.check(OtpRequest("0096891234568", "login", timestamp=T0 + 2))
    g.report_verified(d1.request_id, T0 + 30)
    with audit.engine.connect() as c:
        assert c.execute(select(func.count()).select_from(otp_events)).scalar() == 3
        assert c.execute(select(otp_events.c.verified_at).where(
            otp_events.c.request_id == d1.request_id)).scalar() is not None
        rows = c.execute(select(alerts.c.scope, alerts.c.hits)).all()
    assert rows == [("country:OM", 2)]


def test_http_service():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from otpsentinel.server import create_app
    app = create_app(Sentinel(Policy.from_dict({"mode": "enforce", "countries": {"OM": {"deny": True}}})))
    c = TestClient(app)
    assert c.get("/health").json()["ok"] is True
    r = c.post("/v1/check", json={"phone": "0096891234567", "purpose": "login"}).json()
    assert r["action"] == "block" and r["allowed"] is False and "reasons" not in r
    ok = c.post("/v1/check", json={"phone": "0512345678", "purpose": "login"}).json()
    assert c.post("/v1/verified", json={"request_id": ok["request_id"]}).status_code == 200
    assert c.post("/v1/verified", json={"request_id": "missing"}).status_code == 404


def test_replay_finds_injected_pumping(tmp_path):
    base = tmp_path / "base.csv"
    mixed = tmp_path / "mixed.csv"
    start = _ts("2026-01-05")
    sim.write(sim.baseline(4, start, otp_per_hour=200, seed=2), base)
    sim.write(sim.merge(sim.read(base), sim.attack("A1", start + 3.5 * 86400, 3, 100, seed=3)), mixed)
    rep = replay(mixed, Policy.load("examples/policy.yaml"), Mapping.load("examples/mapping-synthetic.yaml"))
    lab = rep["labelled"]
    assert lab["per_scenario"]["A1"]["recall"] > 0.6
    assert lab["false_positive_rate"] < 0.01
    assert "D3" in rep["inactive_detectors"]


def test_simulator_scenarios_are_labelled():
    start = _ts("2026-01-05")
    for sc in sim.SCENARIOS:
        if sc in ("A5", "A7"):
            continue
        rows = list(sim.attack(sc, start, 1, 60, seed=1))
        assert rows and all(r.label == sc for r in rows)
        assert rows == sorted(rows, key=lambda r: r.ts)
    a5 = list(sim.attack("A5", start, 1, 0, existing=["+966500000001", "+966500000002"]))
    assert [r.type for r in a5] == ["otp:reset_password"] * 2
