import pytest

from otpguard import Action, OtpRequest, Policy, Sentinel, Signal
from otpguard.enrich import NetworkParser, PhoneParser, normalize_phone
from otpguard.scoring import combine
from otpguard.store.base import StoreError
from otpguard.store.memory import MemoryStore

T0 = 1_767_600_000.0  # a Monday, 08:00 UTC


def sentinel(**policy):
    p = Policy.from_dict({"mode": "enforce", **policy})
    return Sentinel(p, MemoryStore())


# --- enrich -----------------------------------------------------------------------------
@pytest.mark.parametrize("raw, expected", [
    ("00966512345678", "+966512345678"),
    ("966512345678", "+966512345678"),
    ("+966 51 234 5678", "+966512345678"),
    ("0512345678", "0512345678"),
    ("", ""),
])
def test_normalize_phone(raw, expected):
    assert normalize_phone(raw, "SA") == expected


def test_phone_parser_regions_and_prefix():
    pp = PhoneParser(b"k", "SA", 3)
    sa = pp.parse("0512345678")
    om = pp.parse("0096891234567")
    assert (sa.region, sa.e164, sa.prefix) == ("SA", "+966512345678", "+966512")
    assert om.region == "OM" and om.calling_code == 968
    assert pp.parse("00966512345678").hash == sa.hash          # same number, same hash
    assert PhoneParser(b"other", "SA").parse("0512345678").hash != sa.hash
    assert pp.parse("not a number").region == "ZZ"


def test_network_parser():
    n = NetworkParser().parse("203.0.113.77")
    assert n.net == "203.0.113.0/24" and n.asn is None
    assert NetworkParser().parse("2001:db8:1:2::5").net == "2001:db8:1::/48"
    assert NetworkParser().parse("nope") is None


# --- policy -----------------------------------------------------------------------------
def test_policy_loads_example():
    p = Policy.load("examples/policy.yaml")
    assert p.purpose("register").cap_24h == 8
    assert p.purpose("unknown").cap_24h == p.default_purpose.cap_24h
    assert p.country("SA").risk == 0.0
    assert p.country("ZW").budget_per_hour == 6          # falls back to the default rule
    assert p.in_campaign(Policy.load("examples/policy.yaml").campaigns[0].start + 10)


def test_policy_rejects_bad_mode():
    with pytest.raises(ValueError):
        Policy.from_dict({"mode": "maybe"})


# --- scoring ----------------------------------------------------------------------------
def test_noisy_or():
    p = Policy.from_dict({"detectors": {"D5": {"weight": 0.5}, "D6": {"weight": 0.5}}})
    risk, action, _, _ = combine([Signal("D5", 1.0, "a"), Signal("D6", 1.0, "b")], p, "login")
    assert risk == pytest.approx(0.75)
    assert action is Action.CHALLENGE


def test_hard_rule_wins_and_challenge_can_be_cleared():
    p = Policy()
    risk, action, reasons, retry = combine(
        [Signal("D2", 0.2, "x"), Signal("D1", 1.0, "cap", force=Action.BLOCK, retry_after=3600)], p, "login")
    assert action is Action.BLOCK and reasons[0].detector == "D1" and retry == 3600
    _, action, _, _ = combine([Signal("D7", 0.9, "pace")], Policy.from_dict({"detectors": {"D7": {"weight": 0.9}}}),
                              "login", challenge_passed=True)
    assert action is Action.ALLOW


# --- detectors --------------------------------------------------------------------------
def test_purpose_cap_blocks_and_counts_only_sent():
    g = sentinel(purposes={"register": {"cap_1h": 2, "cap_24h": 3}})
    acts = [g.check(OtpRequest("0512345678", "register", timestamp=T0 + i)).action for i in range(4)]
    assert acts == [Action.ALLOW, Action.ALLOW, Action.BLOCK, Action.BLOCK]
    # a different purpose has its own cap
    assert g.check(OtpRequest("0512345678", "login", timestamp=T0 + 10)).action is Action.ALLOW


def test_destination_rules():
    g = sentinel(countries={"OM": {"deny": True}}, prefixes={"+96650": 1.0})
    assert g.check(OtpRequest("0096891234567", "login", timestamp=T0)).action is Action.BLOCK
    assert g.check(OtpRequest("0501234567", "login", timestamp=T0)).action is Action.BLOCK
    assert g.check(OtpRequest("0551234567", "login", timestamp=T0)).action is Action.ALLOW


def test_resend_without_verify_and_feedback():
    g = sentinel(purposes={"login": {"cap_1h": 50, "cap_24h": 50}}, detectors={"D3": {"weight": 1.0, "k": 3}})
    ds = [g.check(OtpRequest("0512345678", "login", timestamp=T0 + 60 * i, is_resend=i > 0)) for i in range(4)]
    assert any(s.detector == "D3" for s in ds[3].reasons)
    # once a code is entered, the same pattern is fine
    g2 = sentinel(purposes={"login": {"cap_1h": 50, "cap_24h": 50}}, detectors={"D3": {"weight": 1.0, "k": 3}})
    for i in range(4):
        d = g2.check(OtpRequest("0512345678", "login", timestamp=T0 + 60 * i))
        g2.report_verified(d.request_id, T0 + 60 * i + 20)
    assert not any(s.detector == "D3" for s in d.reasons)


def test_pacing_detects_metronome_not_poisson():
    import random
    rng = random.Random(4)
    g = sentinel(purposes={"reset_password": {"cap_1h": 9, "cap_24h": 9}},
                 detectors={"D7": {"weight": 1.0}})
    t = T0
    for i in range(60):               # human-like traffic: exponential gaps
        t += rng.expovariate(1 / 120)
        d = g.check(OtpRequest(f"05{i:08d}", "reset_password", timestamp=t))
    assert not any(s.detector == "D7" for s in d.reasons)
    for i in range(60):               # a script: one request every 3 seconds
        t += 3
        d = g.check(OtpRequest(f"05{50_000_000 + i:08d}", "reset_password", timestamp=t))
    assert any(s.detector == "D7" for s in d.reasons)


def test_spend_budget_challenges_then_blocks():
    g = sentinel(countries={"OM": {"price": 1.0, "budget_per_hour": 3}},
                 purposes={"login": {"cap_1h": 9, "cap_24h": 9}})
    acts = [g.check(OtpRequest(f"00968912345{i:02d}", "login", timestamp=T0 + i)).action for i in range(8)]
    assert acts[:3] == [Action.ALLOW] * 3
    assert Action.CHALLENGE in acts
    assert acts[-1] is Action.BLOCK or Action.CHALLENGE in acts[3:]


def test_client_integrity():
    g = sentinel(detectors={"D10": {"weight": 1.0}})
    d = g.check(OtpRequest("0512345678", "login", timestamp=T0, session_id="s1", session_age_ms=40))
    assert d.reasons and d.reasons[0].detector == "D10"
    d = g.check(OtpRequest("0512345679", "login", timestamp=T0, attestation="failed"))
    assert d.action is Action.BLOCK


# --- sentinel ---------------------------------------------------------------------------
def test_shadow_mode_always_allows_sending():
    g = Sentinel(Policy.from_dict({"mode": "shadow", "countries": {"OM": {"deny": True}}}))
    d = g.check(OtpRequest("0096891234567", "login", timestamp=T0))
    assert d.action is Action.BLOCK and d.allowed and not d.enforced


def test_report_verified_unknown_id():
    assert Sentinel().report_verified("nope") is False


class BrokenStore(MemoryStore):
    def incr(self, *a, **k):
        raise StoreError("down")


def test_fail_open_and_closed():
    g = Sentinel(Policy.from_dict({"mode": "enforce"}), BrokenStore())
    assert g.check(OtpRequest("0512345678", "login", timestamp=T0)).action is Action.ALLOW
    g = Sentinel(Policy.from_dict({"mode": "enforce", "fail_mode": "closed"}), BrokenStore())
    assert g.check(OtpRequest("0512345678", "login", timestamp=T0)).action is Action.BLOCK


def test_reasons_never_contain_the_number():
    g = sentinel(purposes={"login": {"cap_1h": 1, "cap_24h": 1}})
    g.check(OtpRequest("0512345678", "login", timestamp=T0))
    d = g.check(OtpRequest("0512345678", "login", timestamp=T0 + 5))
    text = " ".join(s.detail + s.scope for s in d.reasons)
    assert "512345678" not in text
