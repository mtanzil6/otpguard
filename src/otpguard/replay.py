"""Replay a historical SMS log through a policy and report what would have happened."""
from __future__ import annotations

import bisect
import csv
import gzip
import io
import json
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, tzinfo
from pathlib import Path
from typing import Any, Iterator
from zoneinfo import ZoneInfo

import yaml

from .model import Action, OtpRequest
from .policy import Policy, _ts
from .sentinel import Sentinel
from .store.memory import MemoryStore

DAY = 86400


@dataclass
class Mapping:
    ts_col: str = "timestamp"
    phone_col: str = "phone"
    type_col: str = "type"
    ip_col: str | None = None
    label_col: str | None = None
    ts_format: str | None = None
    otp: dict[str, tuple[str, bool]] = field(default_factory=dict)    # type -> (purpose, is_resend)
    events: dict[str, str] = field(default_factory=dict)              # type -> event kind (fed to D11)
    customer_types: set[str] = field(default_factory=set)             # types that mark a real customer
    verification: bool = False
    customer_window_days: int = 7
    tz: tzinfo = timezone.utc                                          # zone of naive timestamps
    customer_proxy_is_d11_input: bool = True

    @classmethod
    def load(cls, path: str | Path) -> "Mapping":
        d = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        cols = d.get("columns", {})
        m = cls(ts_col=cols.get("timestamp", "timestamp"), phone_col=cols.get("phone", "phone"),
                type_col=cols.get("type", "type"), ip_col=cols.get("ip"), label_col=cols.get("label"),
                ts_format=d.get("timestamp_format"),
                verification=bool(d.get("feedback", {}).get("verification", False)),
                customer_window_days=int(d.get("customer_window_days", 7)))
        for t, v in (d.get("otp") or {}).items():
            purpose, _, flag = str(v).partition("+")
            m.otp[str(t)] = (purpose, flag == "resend")
        m.events = {str(k): str(v) for k, v in (d.get("events") or {}).items()}
        # The customer proxy must not be the same signal D11 reads, or the collateral
        # figure grades a detector on its own input. If ``customer_events`` is not
        # given, the event types are used for both (and the report says so).
        ce = d.get("customer_events")
        m.customer_types = {str(x) for x in ce} if ce else set(m.events)
        m.customer_proxy_is_d11_input = ce is None
        if d.get("timezone"):
            m.tz = ZoneInfo(str(d["timezone"]))
        return m


@dataclass
class Incident:
    id: str
    label: str                     # abuse | legitimate | operational | unlabelled
    start: float
    end: float
    purposes: set[str] | None = None
    countries: set[str] | None = None
    baseline_per_day: float | None = None

    def matches(self, ts: float, purpose: str, cc: str) -> bool:
        if not (self.start <= ts < self.end):
            return False
        if self.purposes and purpose not in self.purposes:
            return False
        if self.countries and cc not in self.countries:
            return False
        return True


def load_incidents(path: str | Path, tz: tzinfo = timezone.utc) -> list[Incident]:
    d = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
    out = []
    for x in d:
        windows = x.get("windows") or [{"start": x["start"], "end": x["end"]}]
        for i, w in enumerate(windows):
            out.append(Incident(id=x["id"] if len(windows) == 1 else f"{x['id']}.{i + 1}",
                                label=x.get("label", "unlabelled"),
                                start=_ts(w["start"], tz=tz), end=_ts(w["end"], end=True, tz=tz),
                                purposes=set(x["purposes"]) if x.get("purposes") else None,
                                countries=set(x["countries"]) if x.get("countries") else None,
                                baseline_per_day=x.get("baseline_per_day")))
    return out


def _open(path: str | Path):
    p = str(path)
    if p.endswith(".gz"):
        return io.TextIOWrapper(gzip.open(p, "rb"), encoding="utf-8", errors="replace", newline="")
    return open(p, encoding="utf-8", errors="replace", newline="")


def parse_ts(value: Any, fmt: str | None, tz: tzinfo = timezone.utc) -> float | None:
    """Epoch seconds. Numbers are taken as epoch; naive date-times are in ``tz``."""
    if isinstance(value, (int, float)):
        return float(value)
    v = str(value).strip()
    if not v:
        return None
    try:
        if fmt:
            return datetime.strptime(v, fmt).replace(tzinfo=tz).timestamp()
        if v.replace(".", "", 1).isdigit():
            return float(v)
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        return (dt if dt.tzinfo else dt.replace(tzinfo=tz)).timestamp()
    except ValueError:
        return None


def _rows(path: str | Path) -> Iterator[dict[str, Any]]:
    """CSV or JSON Lines, optionally gzipped."""
    name = str(path)
    if name.endswith(".gz"):
        name = name[:-3]
    with _open(path) as fh:
        if name.endswith((".jsonl", ".ndjson", ".json")):
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)
        else:
            yield from csv.DictReader(fh)


def read_log(path: str | Path, m: Mapping) -> Iterator[dict[str, Any]]:
    for row in _rows(path):
        ts = parse_ts(row.get(m.ts_col, ""), m.ts_format, m.tz)
        if ts is None:
            continue
        yield {"ts": ts, "phone": str(row.get(m.phone_col, "") or ""), "type": str(row.get(m.type_col, "") or ""),
               "ip": row.get(m.ip_col) if m.ip_col else None,
               "label": str(row.get(m.label_col) or "") if m.label_col else ""}


@dataclass
class _Window:
    total: int = 0
    flagged: int = 0
    blocked: int = 0
    first_flag: float | None = None


def replay(log_path: str | Path, policy: Policy, mapping: Mapping, incidents: list[Incident] | None = None,
           as_enforced: bool = True, decisions_out: str | Path | None = None,
           progress_every: int = 0) -> dict[str, Any]:
    policy.verification_feedback = mapping.verification
    if as_enforced:
        policy.mode = "enforce"
    g = Sentinel(policy, MemoryStore())
    incidents = incidents or []
    win = {i.id: _Window() for i in incidents}

    actions = Counter()
    by_day: dict[str, Counter] = defaultdict(Counter)
    fired = Counter()
    top = Counter()
    labels = Counter()            # (label, predicted) pairs
    otp_seen: list[tuple[str, float, bool, tuple[str, ...]]] = []
    customer_events: dict[str, list[float]] = defaultdict(list)
    unmapped = Counter()
    n_rows = n_otp = n_events = 0
    out_fh = writer = None
    if decisions_out:
        out_fh = open(decisions_out, "w", newline="", encoding="utf-8")
        writer = csv.writer(out_fh)
        writer.writerow(["ts", "purpose", "country", "action", "risk", "detectors", "label"])
    t0 = time.time()
    last_ts = None
    for r in read_log(log_path, mapping):
        n_rows += 1
        if last_ts is not None and r["ts"] < last_ts - 3600:
            raise ValueError("log is not in time order; sort it by timestamp first")
        last_ts = r["ts"] if last_ts is None else max(last_ts, r["ts"])
        t = r["type"]
        if t in mapping.events or t in mapping.customer_types:
            if t in mapping.events:
                n_events += 1
                g.report_event(mapping.events[t], r["ts"])
            if t in mapping.customer_types and r["phone"]:
                customer_events[g.phones.parse(r["phone"]).hash].append(r["ts"])
            continue
        spec = mapping.otp.get(t)
        if spec is None:
            unmapped[t] += 1
            continue
        if not r["phone"]:
            continue
        n_otp += 1
        purpose, resend = spec
        d = g.check(OtpRequest(phone=r["phone"], purpose=purpose, timestamp=r["ts"], is_resend=resend,
                               ip=r["ip"] or None))
        flagged = d.action is not Action.ALLOW
        actions[d.action.value] += 1
        day = datetime.fromtimestamp(r["ts"], tz=timezone.utc).strftime("%Y-%m-%d")
        by_day[day]["otp"] += 1
        by_day[day][d.action.value] += 1
        dets = tuple(s.detector for s in d.reasons)
        for det in dets:
            fired[det] += 1
        if flagged and dets:
            top[dets[0]] += 1
        if mapping.label_col is not None:
            labels[(r["label"] or "-", flagged)] += 1
        if not r["label"]:      # injected attack rows are not customers
            otp_seen.append((d.phone_hash, r["ts"], flagged, dets))
        for inc in incidents:
            if inc.matches(r["ts"], purpose, d.country):
                w = win[inc.id]
                w.total += 1
                if flagged:
                    w.flagged += 1
                    if d.action is Action.BLOCK:
                        w.blocked += 1
                    if w.first_flag is None:
                        w.first_flag = r["ts"]
        if writer:
            writer.writerow([int(r["ts"]), purpose, d.country, d.action.value, f"{d.risk:.3f}",
                             " ".join(dets), r["label"]])
        if progress_every and n_otp % progress_every == 0:
            print(f"  {n_otp:,} OTPs replayed ({time.time() - t0:.0f}s)", flush=True)
    if out_fh:
        out_fh.close()

    report: dict[str, Any] = {
        "rows": n_rows, "otp_requests": n_otp, "events": n_events,
        "seconds": round(time.time() - t0, 1),
        "policy_version": policy.version,
        "actions": dict(actions),
        "flagged_share": round((actions["challenge"] + actions["block"]) / max(n_otp, 1), 5),
        "detectors_fired": dict(sorted(fired.items())),
        "top_reason_when_flagged": dict(sorted(top.items())),
        "inactive_detectors": _inactive(policy, mapping),
        "customer_proxy": sorted(mapping.customer_types),
        "customer_proxy_is_d11_input": bool(mapping.customer_proxy_is_d11_input and mapping.events),
        "unmapped_types": dict(unmapped.most_common(20)),
        "by_day": {k: dict(v) for k, v in sorted(by_day.items())},
    }
    if customer_events:
        report["collateral"] = _collateral(otp_seen, customer_events, incidents,
                                           mapping.customer_window_days * DAY)
    if incidents:
        report["incidents"] = {}
        for inc in incidents:
            w = win[inc.id]
            entry: dict[str, Any] = {"label": inc.label, "requests": w.total, "flagged": w.flagged,
                                     "blocked": w.blocked,
                                     "flagged_share": round(w.flagged / w.total, 4) if w.total else None,
                                     "first_flag_after_h": round((w.first_flag - inc.start) / 3600, 2)
                                     if w.first_flag else None}
            if inc.baseline_per_day is not None:
                expected = inc.baseline_per_day * (inc.end - inc.start) / DAY
                excess = max(w.total - expected, 0.0)
                entry["expected"] = round(expected, 1)
                entry["excess"] = round(excess, 1)
                entry["excess_stopped"] = round(min(w.flagged, excess) / excess, 4) if excess else None
            report["incidents"][inc.id] = entry
    if labels:
        report["labelled"] = _label_metrics(labels)
    return report


def _inactive(policy: Policy, mapping: Mapping) -> list[str]:
    out = []
    if not mapping.verification:
        out += ["D3", "D4"]
    if not mapping.ip_col:
        out += ["D8", "D9"]
    out.append("D10")   # logs never carry session tokens
    if not mapping.events:
        out.append("D11")
    return out


def _collateral(otp_seen, customer_events, incidents, horizon: float) -> dict[str, Any]:
    for v in customer_events.values():
        v.sort()

    def is_customer(h: str, ts: float) -> bool:
        ev = customer_events.get(h)
        if not ev:
            return False
        i = bisect.bisect_left(ev, ts)
        return i < len(ev) and ev[i] <= ts + horizon

    total = flagged = 0
    per_window = {i.id: [0, 0] for i in incidents if i.label == "legitimate"}
    legit = [i for i in incidents if i.label == "legitimate"]
    for h, ts, f, _ in otp_seen:
        if not is_customer(h, ts):
            continue
        total += 1
        flagged += f
        for inc in legit:
            if inc.start <= ts < inc.end:
                per_window[inc.id][0] += 1
                per_window[inc.id][1] += f
    return {"customer_otps": total, "customer_otps_flagged": flagged,
            "rate": round(flagged / total, 5) if total else None,
            "legitimate_windows": {k: {"customer_otps": a, "flagged": b,
                                       "rate": round(b / a, 5) if a else None}
                                   for k, (a, b) in per_window.items()}}


def _label_metrics(labels: Counter) -> dict[str, Any]:
    tp = sum(v for (lab, f), v in labels.items() if lab not in ("-", "") and f)
    fn = sum(v for (lab, f), v in labels.items() if lab not in ("-", "") and not f)
    fp = sum(v for (lab, f), v in labels.items() if lab in ("-", "") and f)
    tn = sum(v for (lab, f), v in labels.items() if lab in ("-", "") and not f)
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    f1 = 2 * prec * rec / (prec + rec) if prec and rec else None
    per = {}
    for lab in sorted({lab for lab, _ in labels if lab not in ("-", "")}):
        t = labels[(lab, True)]
        n = t + labels[(lab, False)]
        per[lab] = {"injected": n, "caught": t, "recall": round(t / n, 4) if n else None}
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(prec, 4) if prec is not None else None,
            "recall": round(rec, 4) if rec is not None else None,
            "f1": round(f1, 4) if f1 is not None else None,
            "false_positive_rate": round(fp / (fp + tn), 5) if fp + tn else None,
            "per_scenario": per}


def to_markdown(rep: dict[str, Any]) -> str:
    a = rep["actions"]
    lines = ["# Replay report", "",
             f"- OTP requests: {rep['otp_requests']:,} (plus {rep['events']:,} events), "
             f"replayed in {rep['seconds']} s",
             f"- Would allow {a.get('allow', 0):,}, challenge {a.get('challenge', 0):,}, "
             f"block {a.get('block', 0):,} ({rep['flagged_share']:.2%} flagged)",
             f"- Detectors without data in this log: {', '.join(rep['inactive_detectors']) or 'none'}", ""]
    if "collateral" in rep:
        c = rep["collateral"]
        lines += [f"- Customers (an event within the window) flagged: {c['customer_otps_flagged']:,} of "
                  f"{c['customer_otps']:,} ({(c['rate'] or 0):.2%})"]
        if rep.get("customer_proxy_is_d11_input"):
            lines.append("  (note: the customer proxy is the same event type D11 reads; set "
                         "`customer_events` in the mapping to separate them)")
        lines.append("")
    if rep.get("incidents"):
        lines += ["## Labelled windows", "", "| id | label | requests | flagged | first flag (h) | excess stopped |",
                  "|---|---|---|---|---|---|"]
        for k, v in rep["incidents"].items():
            es = v.get("excess_stopped")
            lines.append(f"| {k} | {v['label']} | {v['requests']:,} | {v['flagged']:,} "
                         f"({(v['flagged_share'] or 0):.1%}) | {v['first_flag_after_h'] if v['first_flag_after_h'] is not None else '–'} "
                         f"| {f'{es:.1%}' if es is not None else '–'} |")
        lines.append("")
    if rep.get("labelled"):
        L = rep["labelled"]
        lines += ["## Injected attacks", "", f"precision {L['precision']}, recall {L['recall']}, F1 {L['f1']}, "
                  f"false-positive rate {L['false_positive_rate']}", "",
                  "| scenario | injected | caught | recall |", "|---|---|---|---|"]
        for k, v in L["per_scenario"].items():
            lines.append(f"| {k} | {v['injected']:,} | {v['caught']:,} | {v['recall']} |")
        lines.append("")
    lines += ["## Detectors", "", "| detector | fired | top reason when flagged |", "|---|---|---|"]
    for k in sorted(set(rep["detectors_fired"]) | set(rep["top_reason_when_flagged"]),
                    key=lambda x: int(x[1:]) if x[1:].isdigit() else 99):
        lines.append(f"| {k} | {rep['detectors_fired'].get(k, 0):,} | {rep['top_reason_when_flagged'].get(k, 0):,} |")
    return "\n".join(lines) + "\n"


def write_report(rep: dict[str, Any], out_dir: str | Path) -> tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    j, m = out / "replay.json", out / "replay.md"
    j.write_text(json.dumps(rep, indent=2), encoding="utf-8")
    m.write_text(to_markdown(rep), encoding="utf-8")
    return j, m
