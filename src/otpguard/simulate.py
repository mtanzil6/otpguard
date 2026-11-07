"""Synthetic traffic and attack injection, so detection can be measured against exact labels.

Columns written: timestamp (unix seconds), phone, type, ip, label. Types are
``otp:<purpose>``, ``otp:<purpose>+resend`` or ``event:<kind>``; the bundled
examples/mapping-synthetic.yaml maps them for replay."""
from __future__ import annotations

import csv
import heapq
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

FIELDS = ["timestamp", "phone", "type", "ip", "label"]

# rough hourly shape of shopping traffic (index = hour of day), evenings busiest
DIURNAL = [0.9, 0.7, 0.5, 0.35, 0.25, 0.2, 0.2, 0.25, 0.35, 0.5, 0.65, 0.8,
           0.95, 1.0, 1.05, 1.1, 1.15, 1.2, 1.3, 1.45, 1.5, 1.5, 1.35, 1.15]

# (calling code, national length, leading digits, share of traffic)
COUNTRIES = [("966", 9, "5", 0.94), ("971", 9, "5", 0.017), ("968", 8, "9", 0.012),
             ("965", 8, "6", 0.011), ("973", 8, "3", 0.007), ("974", 8, "3", 0.006),
             ("20", 10, "1", 0.004), ("962", 9, "7", 0.003)]

PURPOSES = [("login", 0.52), ("register", 0.30), ("reset_password", 0.05),
            ("change_phone", 0.05), ("login+resend", 0.04), ("register+resend", 0.04)]


@dataclass
class Row:
    ts: float
    phone: str
    type: str
    ip: str = ""
    label: str = ""

    def as_list(self) -> list:
        return [f"{self.ts:.0f}", self.phone, self.type, self.ip, self.label]


def _pick(rng: random.Random, items):
    x, acc = rng.random(), 0.0
    for v, w in items:
        acc += w
        if x <= acc:
            return v
    return items[-1][0]


def _number(rng: random.Random, cc: str, length: int, lead: str) -> str:
    rest = "".join(rng.choice("0123456789") for _ in range(length - len(lead)))
    return f"+{cc}{lead}{rest}"


def _home_ip(rng: random.Random, n_nets: int = 1500) -> str:
    # customers sit behind carrier NAT, so addresses repeat a lot
    net = rng.randrange(n_nets)
    return f"10.{net // 250}.{net % 250}.{rng.randrange(1, 9)}"


def baseline(days: int, start: float, otp_per_hour: float = 400.0, seed: int = 1,
             surge: tuple[float, float, float] | None = None) -> Iterator[Row]:
    """Legitimate traffic: returning customers, new sign-ups, orders following logins.
    ``surge`` = (start, end, multiplier) adds a sale-like peak."""
    rng = random.Random(seed)
    customers: list[tuple[str, str]] = []
    for _ in range(int(otp_per_hour * 60)):
        cc, ln, lead = _pick(rng, [((c, l, d), w) for c, l, d, w in COUNTRIES])
        customers.append((_number(rng, cc, ln, lead), _home_ip(rng)))
    t, end = start, start + days * 86400
    pending: list[tuple[float, str, str]] = []      # (ts, phone, kind) events in the future
    while t < end:
        h = int((t // 3600) % 24)
        rate = otp_per_hour * DIURNAL[h] / 3600
        if surge and surge[0] <= t < surge[1]:
            rate *= surge[2]
        t += rng.expovariate(rate)
        while pending and pending[0][0] <= t:
            ts, ph, kind = heapq.heappop(pending)
            yield Row(ts, ph, f"event:{kind}")
        purpose = _pick(rng, PURPOSES)
        base_purpose = purpose.split("+")[0]
        if base_purpose == "register":
            cc, ln, lead = _pick(rng, [((c, l, d), w) for c, l, d, w in COUNTRIES])
            phone, ip = _number(rng, cc, ln, lead), _home_ip(rng)
            if rng.random() < 0.85:
                customers.append((phone, ip))
        else:
            phone, ip = customers[int(rng.random() ** 1.3 * len(customers))]
            if rng.random() < 0.15:
                ip = _home_ip(rng)
        yield Row(t, phone, f"otp:{purpose}", ip)
        if base_purpose in ("login", "register") and rng.random() < 0.35:
            heapq.heappush(pending, (t + rng.uniform(600, 3 * 86400), phone, "order"))
    while pending:
        ts, ph, kind = heapq.heappop(pending)
        if ts < end:
            yield Row(ts, ph, f"event:{kind}")


def attack(scenario: str, start: float, hours: float, rate_per_hour: float, seed: int = 7,
           existing: list[str] | None = None) -> Iterator[Row]:
    """Attack traffic for scenarios A1–A6 (A7 is A1 injected during a surge)."""
    rng = random.Random(seed)
    end = start + hours * 3600
    label = scenario
    if scenario in ("A1", "A2", "A4", "A7"):
        pool = [_number(rng, "968", 8, "9") for _ in range(150)]
        ips = [f"198.51.100.{i}" for i in range(1, 6)]
        t = start
        while True:
            t += rng.expovariate(rate_per_hour / 3600)
            if t >= end:
                return
            ph = rng.choice(pool)
            if scenario == "A2":
                ip = f"{rng.randrange(11, 223)}.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"
            else:
                ip = rng.choice(ips)
            typ = "otp:register+resend" if rng.random() < 0.3 else "otp:register"
            yield Row(t, ph, typ, ip, label)
    elif scenario == "A3":
        base = 2348031000000
        t, i = start, 0
        while True:
            t += rng.expovariate(rate_per_hour / 3600)
            if t >= end:
                return
            i += rng.randrange(1, 4)
            yield Row(t, f"+{base + i}", "otp:register",
                      f"203.0.113.{rng.randrange(1, 255)}", label)
    elif scenario == "A5":
        targets = list(existing or [])
        rng.shuffle(targets)
        t = start
        for ph in targets:
            t += rng.uniform(3, 5)
            if t >= end:
                return
            yield Row(t, ph, "otp:reset_password", f"192.0.2.{rng.randrange(1, 255)}", label)
    elif scenario == "A6":
        pool = [_number(rng, "966", 9, "5") for _ in range(30)]
        streams = []
        for ph in pool:
            t = start + rng.uniform(0, hours * 3600 * 0.5)
            for _ in range(int(rng.uniform(15, 30))):
                t += rng.uniform(60, 90)
                if t < end:
                    streams.append(Row(t, ph, "otp:login+resend", "198.18.0.9", label))
        yield from sorted(streams, key=lambda r: r.ts)
    else:
        raise ValueError(f"unknown scenario {scenario!r}; use A1..A7")


def merge(*streams: Iterable[Row]) -> Iterator[Row]:
    return heapq.merge(*streams, key=lambda r: r.ts)


def write(rows: Iterable[Row], path: str | Path) -> int:
    n = 0
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(FIELDS)
        for r in rows:
            w.writerow(r.as_list())
            n += 1
    return n


def read(path: str | Path) -> Iterator[Row]:
    with open(path, encoding="utf-8", newline="") as fh:
        for d in csv.DictReader(fh):
            yield Row(float(d["timestamp"]), d["phone"], d["type"], d.get("ip", ""), d.get("label", ""))


def customers_in(path: str | Path, limit: int = 5000, seed: int = 3,
                 customer_types: Iterable[str] | None = None) -> list[str]:
    """Numbers that look like real customers: those that received one of
    ``customer_types`` (default: any ``event:`` row). For a real log pass the shipping
    or delivery message types."""
    types = set(customer_types or ())
    rows = list(read(path))
    if not types:
        # an imported real log marks customers with type "customer"; synthetic logs use events
        types = {"customer"} if any(r.type == "customer" for r in rows) else set()
    seen = {r.phone for r in rows
            if ((r.type in types) if types else r.type.startswith("event:"))}
    out = sorted(seen)
    random.Random(seed).shuffle(out)
    return out[:limit]


def otp_rate_per_hour(path: str | Path, otp_types: Iterable[str] | None = None) -> float:
    """Mean OTP requests per hour in a log, for ``--volume`` (attack rate as a fraction
    of the legitimate rate)."""
    types = set(otp_types or ())
    n, t0, t1 = 0, None, None
    for r in read(path):
        if ((r.type in types) if types else r.type.startswith("otp:")):
            n += 1
            t0 = r.ts if t0 is None else min(t0, r.ts)
            t1 = r.ts if t1 is None else max(t1, r.ts)
    if not n or t1 == t0:
        return 0.0
    return n / ((t1 - t0) / 3600)


# (ASN label, share of customers, number of /24 networks it holds). Used to give a
# log with no addresses plausible ones, so that A2's fresh residential addresses
# stand against something. Stated, not measured; replace with your own mix.
DEFAULT_ASN_MIX = [("stc", 0.45, 600), ("mobily", 0.30, 400), ("zain", 0.20, 300), ("other", 0.05, 200)]


def assign_ips(rows: Iterable[Row], mix: list[tuple[str, float, int]] | None = None,
               seed: int = 11, churn: float = 0.15) -> Iterator[Row]:
    """Give rows without an IP a synthetic one. Each number gets a home network in an
    ASN drawn from ``mix``; ``churn`` is the chance a request comes from another
    address in the same ASN (mobile users move between NAT pools). Labelled attack
    rows that already carry an IP are left alone."""
    mix = mix or DEFAULT_ASN_MIX
    rng = random.Random(seed)
    homes: dict[str, tuple[int, int]] = {}
    base = {}
    off = 0
    for i, (_, _, nets) in enumerate(mix):
        base[i] = off
        off += nets
    for r in rows:
        if r.ip:
            yield r
            continue
        h = homes.get(r.phone)
        if h is None:
            asn = _pick(rng, [(i, share) for i, (_, share, _) in enumerate(mix)])
            h = (asn, rng.randrange(mix[asn][2]))
            homes[r.phone] = h
        asn, net = h
        if rng.random() < churn:
            net = rng.randrange(mix[asn][2])
        n = base[asn] + net
        yield Row(r.ts, r.phone, r.type, f"10.{n // 250}.{n % 250}.{rng.randrange(1, 9)}", r.label)


def import_log(log_path: str | Path, mapping_path: str | Path) -> tuple[Iterator[Row], dict]:
    """Convert a real log (any columns, read through a replay mapping) to the simulator's
    schema, so attacks can be injected into it. OTP types become ``otp:<purpose>`` (with
    ``+resend``), D11 event types ``event:<kind>``, and customer-proxy types ``customer``
    (a row that is both is written twice). Timestamps become epoch seconds, so the time
    zone is applied once, here. Returns the rows and a mapping for replaying the result."""
    from .replay import Mapping, read_log   # local import: replay imports this module's users
    m = Mapping.load(mapping_path)

    def rows() -> Iterator[Row]:
        for r in read_log(log_path, m):
            t, ph, ip = r["type"], r["phone"], r["ip"] or ""
            if t in m.otp:
                purpose, resend = m.otp[t]
                yield Row(r["ts"], ph, f"otp:{purpose}{'+resend' if resend else ''}", ip, r["label"])
                continue
            if t in m.events:
                yield Row(r["ts"], ph, f"event:{m.events[t]}", ip, r["label"])
            if t in m.customer_types:
                yield Row(r["ts"], ph, "customer", ip, r["label"])

    kinds = sorted(set(m.events.values()))
    purposes = sorted({f"{p}{'+resend' if rs else ''}" for p, rs in m.otp.values()})
    # attacks are always written as register / reset_password / login(+resend) OTPs
    purposes = sorted(set(purposes) | {"register", "register+resend", "reset_password", "login+resend"})
    companion = {
        "columns": {"timestamp": "timestamp", "phone": "phone", "type": "type", "ip": "ip", "label": "label"},
        "otp": {f"otp:{p}": p for p in purposes},
        "events": {f"event:{k}": k for k in kinds},
        "customer_events": ["customer"] if m.customer_types else [f"event:{k}" for k in kinds],
        "customer_window_days": m.customer_window_days,
        "feedback": {"verification": m.verification},
    }
    return rows(), companion


SCENARIOS = {
    "A1": "pumping to one foreign country from a few IPs",
    "A2": "A1 with a fresh IP for every request",
    "A3": "fresh numbers drawn sequentially from one prefix",
    "A4": "low and slow: a few percent above normal for days",
    "A5": "one password reset to each of many existing customers, evenly paced",
    "A6": "repeated resends to the same numbers without verification",
    "A7": "A1 during a legitimate traffic surge",
}


def scenario_defaults(s: str) -> dict[str, float]:
    return {"A1": {"hours": 6, "rate": 120}, "A2": {"hours": 6, "rate": 120},
            "A3": {"hours": 2, "rate": 300}, "A4": {"hours": 120, "rate": 8},
            "A5": {"hours": 4, "rate": 0}, "A6": {"hours": 1, "rate": 0},
            "A7": {"hours": 6, "rate": 120}}[s]
