"""Inject each attack scenario into traffic and replay it, over several seeds and
attack volumes, against the full policy, a conventional limiter and layer ablations.

    python benchmarks/run_scenarios.py --out benchmarks/results
    python benchmarks/run_scenarios.py --seeds 10 --volumes 0.01 0.05 0.1 0.2
    python benchmarks/run_scenarios.py --base real_log.csv --mapping mapping.yaml   # a real log

Writes scenarios.json and scenarios.md (mean and 95 % interval over seeds). With no
--base the legitimate traffic is synthetic; use `otpguard replay` on your own logs
for numbers that mean something for your service."""
from __future__ import annotations

import argparse
import json
import math
import statistics
import tempfile
import time
from pathlib import Path

from otpguard import simulate as sim
from otpguard.policy import Policy, _ts
from otpguard.replay import Mapping, replay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
START = "2026-01-05"
DAYS = 28
ATTACK_AT = "2026-01-26T10:00"   # after three weeks of history
SURGE = ("2026-01-24", "2026-01-27", 3.0)

LAYERS = {"L1": ["D1", "D2"], "L2": ["D3", "D4"], "L3": ["D5", "D6", "D7", "D8", "D9", "D10", "D11"],
          "L4": ["D12"]}
ALL_DETECTORS = [d for ds in LAYERS.values() for d in ds]


def design_policy(policy_path: Path, design: str) -> Policy:
    """'full', 'limiter' (D1 caps plus a per-IP cap, no scoring), or 'without-Lx'."""
    p = Policy.load(policy_path)
    if design == "limiter":
        for det in ALL_DETECTORS:
            if det not in ("D1", "D8"):
                p.detectors.setdefault(det, {})["enabled"] = False
        # D8 as a plain per-IP cap: block above per_ip requests in its window, nothing else
        p.detectors["D8"].update({"per_net": 10 ** 9, "per_asn": 10 ** 9, "hosting_score": 0.0,
                                  "hard_cap": True})
        p.version = p.version + "+limiter"
    elif design.startswith("without-"):
        for det in LAYERS[design.split("-", 1)[1]]:
            p.detectors.setdefault(det, {})["enabled"] = False
        p.version = p.version + "+" + design
    return p


def ci95(xs: list[float]) -> tuple[float, float, float]:
    xs = [x for x in xs if x is not None]
    if not xs:
        return float("nan"), float("nan"), float("nan")
    m = statistics.fmean(xs)
    if len(xs) < 2:
        return m, m, m
    h = 1.96 * statistics.stdev(xs) / math.sqrt(len(xs))
    return m, m - h, m + h


def run(policy_path: Path, out: Path, seeds: list[int], volumes: list[float | None],
        scenarios: list[str] | None, designs: list[str], base_log: Path | None = None,
        mapping_path: Path | None = None, attack_at: str = ATTACK_AT) -> dict:
    mapping = Mapping.load(mapping_path or ROOT / "examples" / "mapping-synthetic.yaml")
    tmp = Path(tempfile.mkdtemp(prefix="otps-"))
    results: dict = {"seeds": seeds, "volumes": volumes, "designs": designs, "runs": []}
    scenarios = scenarios or sorted(sim.SCENARIOS)
    for seed in seeds:
        if base_log is None:
            base = tmp / f"base{seed}.csv"
            surge = tmp / f"surge{seed}.csv"
            sim.write(sim.baseline(DAYS, _ts(START), seed=seed), base)
            sim.write(sim.baseline(DAYS, _ts(START), seed=seed,
                                   surge=(_ts(SURGE[0]), _ts(SURGE[1], end=True), SURGE[2])), surge)
        else:
            base = surge = base_log
        base_rate = sim.otp_rate_per_hour(base, list(mapping.otp))
        for sc in scenarios:
            d = sim.scenario_defaults(sc)
            src = surge if sc == "A7" else base
            start = attack_at if sc != "A5" else attack_at[:10] + "T01:00"
            existing = sim.customers_in(src, seed=seed, customer_types=mapping.customer_types) \
                if sc == "A5" else None
            for vol in volumes:
                rate = d["rate"] if vol is None else vol * base_rate
                mixed = tmp / f"{sc}-{seed}-{vol}.csv"
                sim.write(sim.merge(sim.read(src),
                                    sim.attack(sc, _ts(start), d["hours"], rate, seed + 6, existing)), mixed)
                for design in designs:
                    policy = design_policy(policy_path, design)
                    t0 = time.time()
                    rep = replay(mixed, policy, mapping)
                    lab = rep["labelled"]
                    per = lab["per_scenario"].get(sc, {})
                    results["runs"].append({
                        "scenario": sc, "seed": seed, "volume": vol, "design": design,
                        "injected": per.get("injected", 0), "recall": per.get("recall"),
                        "precision": lab["precision"], "f1": lab["f1"],
                        "false_positive_rate": lab["false_positive_rate"],
                        "customer_collateral": rep.get("collateral", {}).get("rate"),
                        "top_reasons": rep["top_reason_when_flagged"],
                        "otp_per_second": round(rep["otp_requests"] / max(time.time() - t0, 1e-9)),
                    })
                    print(f"{sc} seed {seed} vol {vol} {design}: recall {per.get('recall')}, "
                          f"precision {lab['precision']}, FPR {lab['false_positive_rate']}", flush=True)
    out.mkdir(parents=True, exist_ok=True)
    results["summary"] = summarize(results["runs"])
    (out / "scenarios.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (out / "scenarios.md").write_text(to_markdown(results), encoding="utf-8")
    return results


def summarize(runs: list[dict]) -> list[dict]:
    groups: dict[tuple, list[dict]] = {}
    for r in runs:
        groups.setdefault((r["scenario"], r["volume"], r["design"]), []).append(r)
    out = []
    for (sc, vol, design), rs in sorted(groups.items(), key=lambda kv: (kv[0][0], str(kv[0][1]), kv[0][2])):
        row = {"scenario": sc, "volume": vol, "design": design, "n": len(rs),
               "injected": statistics.fmean(r["injected"] for r in rs)}
        for m in ("recall", "precision", "f1", "false_positive_rate", "customer_collateral"):
            mean, lo, hi = ci95([r[m] for r in rs])
            row[m] = {"mean": mean, "lo": lo, "hi": hi}
        reasons: dict[str, int] = {}
        for r in rs:
            for k, v in r["top_reasons"].items():
                reasons[k] = reasons.get(k, 0) + v
        row["top_reasons"] = sorted(reasons, key=lambda k: -reasons[k])[:3]
        out.append(row)
    return out


def _fmt(m: dict, digits: int = 3) -> str:
    if m["mean"] != m["mean"]:
        return "–"
    lo, hi = max(0.0, m["lo"]), min(1.0, m["hi"])     # proportions
    if lo == hi or abs(hi - lo) < 10 ** -digits:
        return f"{m['mean']:.{digits}f}"
    return f"{m['mean']:.{digits}f} [{lo:.{digits}f}, {hi:.{digits}f}]"


def to_markdown(results: dict) -> str:
    lines = [f"Seeds: {results['seeds']}; volumes (fraction of legitimate OTP rate, None = scenario "
             f"default): {results['volumes']}. Mean [95 % interval] over seeds.", "",
             "| scenario | volume | design | injected | recall | precision | F1 | FPR | customer collateral | main detectors |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for r in results["summary"]:
        lines.append(f"| {r['scenario']} {sim.SCENARIOS[r['scenario']]} | {r['volume'] if r['volume'] is not None else 'default'} "
                     f"| {r['design']} | {r['injected']:,.0f} | {_fmt(r['recall'])} | {_fmt(r['precision'])} | "
                     f"{_fmt(r['f1'])} | {_fmt(r['false_positive_rate'], 5)} | {_fmt(r['customer_collateral'], 5)} | "
                     f"{', '.join(r['top_reasons'])} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", default=str(ROOT / "examples" / "policy.yaml"))
    ap.add_argument("--out", default=str(HERE / "results"))
    ap.add_argument("--seeds", type=int, default=1, help="number of seeds (1..N)")
    ap.add_argument("--seed-start", type=int, default=1)
    ap.add_argument("--volumes", type=float, nargs="*",
                    help="attack rates as fractions of the legitimate rate; omit for scenario defaults")
    ap.add_argument("--only", nargs="*", help="scenario ids")
    ap.add_argument("--designs", nargs="*", default=["full"],
                    help="full, limiter, without-L1, without-L2, without-L3, without-L4")
    ap.add_argument("--base", help="a real log (mapping schema) to inject into instead of synthetic traffic")
    ap.add_argument("--mapping", help="mapping file for --base")
    ap.add_argument("--attack-at", default=ATTACK_AT, help="ISO start of the injected attack")
    a = ap.parse_args()
    run(Path(a.policy), Path(a.out), list(range(a.seed_start, a.seed_start + a.seeds)),
        a.volumes or [None], a.only, a.designs, Path(a.base) if a.base else None,
        Path(a.mapping) if a.mapping else None, a.attack_at)
