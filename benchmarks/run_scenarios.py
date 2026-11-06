"""Inject each attack scenario into synthetic traffic and replay it.

    python benchmarks/run_scenarios.py --out benchmarks/results

Writes scenarios.json and scenarios.md. Everything is seeded, so the numbers are
reproducible. The synthetic traffic is a stand-in; use `otpsentinel replay` on your own
logs for numbers that mean something for your service."""
from __future__ import annotations

import argparse
import json
import tempfile
import time
from pathlib import Path

from otpsentinel import simulate as sim
from otpsentinel.policy import Policy, _ts
from otpsentinel.replay import Mapping, replay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
START = "2026-01-05"
DAYS = 28
ATTACK_AT = "2026-01-26T10:00"   # after three weeks of history
SURGE = ("2026-01-24", "2026-01-27", 3.0)


def run(policy_path: Path, out: Path, seed: int = 1, scenarios: list[str] | None = None,
        disable: list[str] | None = None) -> dict:
    mapping = Mapping.load(ROOT / "examples" / "mapping-synthetic.yaml")
    tmp = Path(tempfile.mkdtemp(prefix="otps-"))
    base = tmp / "base.csv"
    surge = tmp / "base_surge.csv"
    sim.write(sim.baseline(DAYS, _ts(START), seed=seed), base)
    sim.write(sim.baseline(DAYS, _ts(START), seed=seed,
                           surge=(_ts(SURGE[0]), _ts(SURGE[1], end=True), SURGE[2])), surge)
    results = {}
    for sc in scenarios or sorted(sim.SCENARIOS):
        d = sim.scenario_defaults(sc)
        src = surge if sc == "A7" else base
        start = ATTACK_AT if sc != "A5" else "2026-01-27T01:00"
        existing = sim.customers_in(src) if sc == "A5" else None
        mixed = tmp / f"{sc}.csv"
        sim.write(sim.merge(sim.read(src), sim.attack(sc, _ts(start), d["hours"], d["rate"], seed + 6,
                                                      existing)), mixed)
        policy = Policy.load(policy_path)
        for det in disable or []:
            policy.detectors.setdefault(det, {})["enabled"] = False
        t0 = time.time()
        rep = replay(mixed, policy, mapping)
        lab = rep["labelled"]
        results[sc] = {
            "description": sim.SCENARIOS[sc],
            "injected": lab["per_scenario"].get(sc, {}).get("injected", 0),
            "recall": lab["per_scenario"].get(sc, {}).get("recall"),
            "precision": lab["precision"],
            "f1": lab["f1"],
            "false_positive_rate": lab["false_positive_rate"],
            "customer_collateral": rep.get("collateral", {}).get("rate"),
            "top_reasons": rep["top_reason_when_flagged"],
            "otp_per_second": round(rep["otp_requests"] / max(time.time() - t0, 1e-9)),
        }
        print(f"{sc}: recall {results[sc]['recall']}, precision {results[sc]['precision']}, "
              f"FPR {results[sc]['false_positive_rate']}", flush=True)
    out.mkdir(parents=True, exist_ok=True)
    (out / "scenarios.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    lines = ["| scenario | injected | recall | precision | F1 | false-positive rate | main detectors |",
             "|---|---|---|---|---|---|---|"]
    for sc, r in results.items():
        topd = ", ".join(k for k, _ in sorted(r["top_reasons"].items(), key=lambda x: -x[1])[:3])
        lines.append(f"| {sc} {r['description']} | {r['injected']:,} | {r['recall']} | {r['precision']} | "
                     f"{r['f1']} | {r['false_positive_rate']} | {topd} |")
    (out / "scenarios.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return results


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", default=str(ROOT / "examples" / "policy.yaml"))
    ap.add_argument("--out", default=str(HERE / "results"))
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--disable", nargs="*", help="detector ids to switch off, for ablation")
    a = ap.parse_args()
    run(Path(a.policy), Path(a.out), a.seed, a.only, a.disable)
