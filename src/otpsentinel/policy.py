"""Policy: every threshold, weight and country rule lives here, loaded from YAML."""
from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone, tzinfo
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import yaml

DEFAULT_DETECTORS: dict[str, dict[str, Any]] = {
    "D1": {"enabled": True},
    "D2": {"enabled": True, "weight": 1.0},
    "D3": {"enabled": True, "weight": 0.6, "window_min": 30, "k": 3},
    "D4": {"enabled": True, "weight": 0.8, "window_min": 60, "min_sent": 20,
           "prior_ratio": 0.7, "prior_strength": 20, "drop": 0.4},
    "D5": {"enabled": True, "weight": 0.7, "window_min": 60, "min_count": 20,
           "ratio_low": 2.0, "ratio_high": 5.0, "min_abs": 0.01, "p_value": 1e-3, "alpha": 0.05},
    "D6": {"enabled": True, "weight": 0.7, "min_new": 8, "p_value": 1e-4, "alpha": 0.05,
           "cold_rate_per_hour": 1.0},
    "D7": {"enabled": True, "weight": 0.6, "last_n": 40, "max_cv": 0.35,
           "min_rate_ratio": 3.0, "per_country": True, "alpha": 0.05},
    "D8": {"enabled": True, "weight": 0.6, "window_min": 10, "per_ip": 10, "per_net": 30,
           "per_asn": 300, "hosting_score": 0.4, "hard_cap": False},
    "D9": {"enabled": True, "weight": 0.5, "min_count": 30, "distinct_ratio": 0.9,
           "new_ip_lift": 0.3},
    "D10": {"enabled": True, "weight": 0.7, "require_session": False, "min_age_ms": 800,
            "max_reuse": 5},
    "D11": {"enabled": True, "weight": 0.5, "window_min": 60, "min_count": 50,
            "ratio": 3.0, "alpha": 0.05, "events": {"reset_password": ["any"]}},
    "D12": {"enabled": True, "block_factor": 2.0},
}


@dataclass
class CountryRule:
    risk: float = 0.0
    deny: bool = False
    budget_per_hour: float | None = None
    budget_per_day: float | None = None
    price: float = 0.0


@dataclass
class PurposeRule:
    # roughly the 99.9th percentile of codes per number on a real e-commerce site
    cap_1h: int = 6
    cap_24h: int = 10
    weights: dict[str, float] = field(default_factory=dict)


@dataclass
class Campaign:
    name: str
    start: float
    end: float


@dataclass
class Policy:
    version: str = "default"
    mode: str = "shadow"                       # shadow | enforce
    secret: str = ""
    default_region: str = "SA"
    home_countries: list[str] = field(default_factory=lambda: ["SA"])
    prefix_digits: int = 3
    timezone: str = "UTC"                      # zone of campaign dates
    challenge_threshold: float = 0.5
    block_threshold: float = 0.85
    verification_feedback: bool = True         # app calls report_verified()
    event_feedback: bool = True                # app calls report_event()
    fail_mode: str = "open"                    # open | closed
    budget_per_hour: float | None = None       # total spend across all countries
    budget_per_day: float | None = None
    challenge_relief: float = 0.3              # weight multiplier for client-side detectors after a solved challenge
    foreign_default_risk: float = 0.2
    default_purpose: PurposeRule = field(default_factory=PurposeRule)
    purposes: dict[str, PurposeRule] = field(default_factory=dict)
    countries: dict[str, CountryRule] = field(default_factory=dict)
    default_country: CountryRule | None = None
    prefixes: dict[str, float] = field(default_factory=dict)   # prefix -> risk (1.0 = deny)
    detectors: dict[str, dict[str, Any]] = field(default_factory=lambda: copy.deepcopy(DEFAULT_DETECTORS))
    campaigns: list[Campaign] = field(default_factory=list)

    # lookups ------------------------------------------------------------------------
    def purpose(self, name: str) -> PurposeRule:
        return self.purposes.get(name, self.default_purpose)

    def country(self, iso: str) -> CountryRule:
        if iso in self.countries:
            return self.countries[iso]
        if iso in self.home_countries:
            # no risk, but the default price still applies so total budgets count home spend
            d = self.default_country
            return CountryRule(risk=0.0, price=d.price if d else 0.0)
        if self.default_country is not None:
            return self.default_country
        return CountryRule(risk=self.foreign_default_risk)

    def det(self, det_id: str) -> dict[str, Any]:
        return self.detectors.get(det_id, {})

    def enabled(self, det_id: str) -> bool:
        return bool(self.det(det_id).get("enabled", True))

    def weight(self, det_id: str, purpose: str) -> float:
        w = self.purpose(purpose).weights.get(det_id)
        if w is None:
            w = self.det(det_id).get("weight", 1.0)
        return float(w)

    def in_campaign(self, ts: float) -> bool:
        return any(c.start <= ts < c.end for c in self.campaigns)

    @property
    def enforce(self) -> bool:
        return self.mode == "enforce"

    def secret_bytes(self) -> bytes:
        s = self.secret or os.environ.get("OTPSENTINEL_SECRET", "")
        if not s:
            # fine for tests and replay; production should always set a secret
            s = "otpsentinel-dev-secret"
        return s.encode()

    # loading ------------------------------------------------------------------------
    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Policy":
        p = cls()
        p.version = str(d.get("version", p.version))
        p.mode = d.get("mode", p.mode)
        if p.mode not in ("shadow", "enforce"):
            raise ValueError(f"mode must be shadow or enforce, not {p.mode!r}")
        secret = d.get("secret", "")
        if isinstance(secret, str) and secret.startswith("env:"):
            secret = os.environ.get(secret[4:], "")
        p.secret = secret
        p.default_region = d.get("default_region", p.default_region)
        p.home_countries = list(d.get("home_countries", p.home_countries))
        p.prefix_digits = int(d.get("prefix_digits", p.prefix_digits))
        p.timezone = str(d.get("timezone", p.timezone))
        tz = ZoneInfo(p.timezone)
        th = d.get("thresholds", {})
        p.challenge_threshold = float(th.get("challenge", p.challenge_threshold))
        p.block_threshold = float(th.get("block", p.block_threshold))
        fb = d.get("feedback", {})
        p.verification_feedback = bool(fb.get("verification", p.verification_feedback))
        p.event_feedback = bool(fb.get("events", p.event_feedback))
        fm = str(d.get("fail_mode", p.fail_mode))
        p.fail_mode = {"open_with_local_limits": "open"}.get(fm, fm)
        if p.fail_mode not in ("open", "closed"):
            raise ValueError(f"fail_mode must be open or closed, not {fm!r}")
        budget = d.get("budget", {}) or {}
        p.budget_per_hour = budget.get("per_hour")
        p.budget_per_day = budget.get("per_day")
        p.challenge_relief = float(d.get("challenge_relief", p.challenge_relief))
        p.foreign_default_risk = float(d.get("foreign_default_risk", p.foreign_default_risk))

        purposes = dict(d.get("purposes", {}) or {})
        if "default" in purposes:
            p.default_purpose = _purpose(purposes.pop("default"), PurposeRule())
        p.purposes = {k: _purpose(v, p.default_purpose) for k, v in purposes.items()}

        countries = dict(d.get("countries", {}) or {})
        if "default" in countries:
            p.default_country = _country(countries.pop("default"))
        p.countries = {k.upper(): _country(v) for k, v in countries.items()}
        p.prefixes = {str(k): float(v) for k, v in (d.get("prefixes", {}) or {}).items()}

        for det_id, cfg in (d.get("detectors", {}) or {}).items():
            base = p.detectors.setdefault(det_id, {})
            base.update(cfg or {})
        p.campaigns = [Campaign(c["name"], _ts(c["start"], tz=tz), _ts(c["end"], end=True, tz=tz))
                       for c in d.get("campaigns", []) or []]
        if p.challenge_threshold > p.block_threshold:
            raise ValueError("challenge threshold must not be above the block threshold")
        return p

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(yaml.safe_load(fh) or {})


def _purpose(v: dict[str, Any] | None, base: PurposeRule) -> PurposeRule:
    v = v or {}
    return PurposeRule(cap_1h=int(v.get("cap_1h", base.cap_1h)),
                       cap_24h=int(v.get("cap_24h", base.cap_24h)),
                       weights={**base.weights, **(v.get("weights") or {})})


def _country(v: dict[str, Any] | None) -> CountryRule:
    v = v or {}
    return CountryRule(risk=float(v.get("risk", 0.0)), deny=bool(v.get("deny", False)),
                       budget_per_hour=v.get("budget_per_hour"), budget_per_day=v.get("budget_per_day"),
                       price=float(v.get("price", 0.0)))


def _ts(v: Any, end: bool = False, tz: tzinfo = timezone.utc) -> float:
    """Epoch seconds for a date, date-time or number. Naive values are in ``tz``; a
    plain date with ``end=True`` means the end of that day."""
    if isinstance(v, (int, float)):
        return float(v)
    if hasattr(v, "year") and not isinstance(v, datetime):   # a plain date from YAML
        dt = datetime(v.year, v.month, v.day, tzinfo=tz)
        return dt.timestamp() + (86400 if end else 0)
    if isinstance(v, datetime):
        return (v if v.tzinfo else v.replace(tzinfo=tz)).timestamp()
    dt = datetime.fromisoformat(str(v))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz)
    if end and len(str(v)) == 10:
        return dt.timestamp() + 86400
    return dt.timestamp()
