"""Decision latency and throughput with every detector enabled (manuscript Table 9).

    python benchmarks/latency.py                       # in-memory store
    python benchmarks/latency.py --redis redis://localhost:6379/1
    python benchmarks/latency.py --n 50000 --out benchmarks/results/latency.json

Requests are a mix of purposes and countries with IPs and session data, so D8–D10
run too; a third of the numbers repeat, so the per-number keys are warm."""
from __future__ import annotations

import argparse
import json
import platform
import random
import statistics
import time
from pathlib import Path

from otpsentinel import OtpRequest, Policy, Sentinel
from otpsentinel.store.memory import MemoryStore

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def requests(n: int, seed: int = 1):
    rng = random.Random(seed)
    cc = [("966", 9, "5", 0.9), ("971", 9, "5", 0.04), ("968", 8, "9", 0.03), ("20", 10, "1", 0.03)]
    purposes = ["login", "register", "reset_password", "change_phone"]
    pool = []
    for i in range(n):
        x, acc = rng.random(), 0.0
        for c, ln, lead, w in cc:
            acc += w
            if x <= acc:
                break
        if pool and rng.random() < 0.33:
            phone = rng.choice(pool)
        else:
            phone = f"+{c}{lead}" + "".join(rng.choice("0123456789") for _ in range(ln - 1))
            pool.append(phone)
        yield OtpRequest(phone=phone, purpose=rng.choice(purposes),
                         ip=f"{rng.randrange(11, 200)}.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}",
                         session_id=f"s{rng.randrange(10 ** 9)}", session_age_ms=rng.randrange(500, 60000))


def bench(store, n: int, policy: Policy, warm: int = 2000) -> dict:
    g = Sentinel(policy, store)
    reqs = list(requests(n + warm))
    for r in reqs[:warm]:
        g.check(r)
    lat = []
    t0 = time.perf_counter()
    for r in reqs[warm:]:
        a = time.perf_counter()
        g.check(r)
        lat.append((time.perf_counter() - a) * 1000)
    wall = time.perf_counter() - t0
    lat.sort()
    q = lambda p: lat[min(len(lat) - 1, int(p * len(lat)))]
    return {"n": n, "p50_ms": round(q(0.50), 3), "p90_ms": round(q(0.90), 3), "p99_ms": round(q(0.99), 3),
            "mean_ms": round(statistics.fmean(lat), 3), "decisions_per_s": round(n / wall)}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20000)
    ap.add_argument("--redis", help="Redis URL; omit for the in-memory store only")
    ap.add_argument("--policy", default=str(ROOT / "examples" / "policy.yaml"))
    ap.add_argument("--out", default=str(HERE / "results" / "latency.json"))
    a = ap.parse_args()
    policy = Policy.load(a.policy)
    policy.mode = "enforce"
    out = {"machine": platform.platform(), "python": platform.python_version(), "cpu": platform.processor(),
           "backends": {}}
    out["backends"]["memory"] = bench(MemoryStore(), a.n, policy)
    print("memory", out["backends"]["memory"], flush=True)
    if a.redis:
        import redis
        from otpsentinel.store.redis_store import RedisStore
        client = redis.Redis.from_url(a.redis)
        client.flushdb()
        out["backends"]["redis"] = bench(RedisStore(client=client, prefix="bench:"), a.n, policy)
        print("redis", out["backends"]["redis"], flush=True)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, indent=2), encoding="utf-8")
    md = ["| backend | p50 (ms) | p99 (ms) | decisions/s |", "|---|---|---|---|"]
    for k, v in out["backends"].items():
        md.append(f"| {k} | {v['p50_ms']} | {v['p99_ms']} | {v['decisions_per_s']:,} |")
    Path(a.out).with_suffix(".md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))
