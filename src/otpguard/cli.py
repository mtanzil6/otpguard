from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from . import simulate as sim
from .model import OtpRequest
from .policy import Policy, _ts


def _policy(path: str | None) -> Policy:
    return Policy.load(path) if path else Policy()


def cmd_check(a) -> int:
    from .sentinel import Sentinel
    g = Sentinel(_policy(a.policy))
    d = g.check(OtpRequest(phone=a.phone, purpose=a.purpose, ip=a.ip))
    print(json.dumps(d.to_dict(), indent=2))
    return 0


def cmd_validate(a) -> int:
    p = Policy.load(a.policy)
    print(f"ok: version {p.version}, mode {p.mode}, {len(p.purposes)} purposes, "
          f"{len(p.countries)} country rules, {len(p.campaigns)} campaigns")
    return 0


def cmd_replay(a) -> int:
    from .replay import Mapping, load_incidents, replay, write_report
    mapping = Mapping.load(a.mapping)
    rep = replay(a.log, _policy(a.policy), mapping,
                 load_incidents(a.incidents, mapping.tz) if a.incidents else None,
                 as_enforced=not a.shadow, decisions_out=a.decisions,
                 progress_every=a.progress)
    j, m = write_report(rep, a.out)
    print(m.read_text(encoding="utf-8"))
    print(f"wrote {j} and {m}")
    return 0


def cmd_sim_baseline(a) -> int:
    surge = (_ts(a.surge[0]), _ts(a.surge[1], end=True), float(a.surge[2])) if a.surge else None
    n = sim.write(sim.baseline(a.days, _ts(a.start), a.rate, a.seed, surge), a.out)
    print(f"wrote {n:,} rows to {a.out}")
    return 0


def cmd_sim_inject(a) -> int:
    d = sim.scenario_defaults(a.scenario)
    hours = a.hours if a.hours is not None else d["hours"]
    rate = a.rate if a.rate is not None else d["rate"]
    otp_types = a.otp_types.split(",") if a.otp_types else None
    if a.volume is not None:
        rate = a.volume * sim.otp_rate_per_hour(a.base, otp_types)
    ctypes = a.customer_types.split(",") if a.customer_types else None
    existing = sim.customers_in(a.base, customer_types=ctypes) if a.scenario == "A5" else None
    attack = sim.attack(a.scenario, _ts(a.start), hours, rate, a.seed, existing)
    n = sim.write(sim.merge(sim.read(a.base), attack), a.out)
    print(f"wrote {n:,} rows to {a.out} ({a.scenario}: {sim.SCENARIOS[a.scenario]}, "
          f"{rate:.0f} attack requests/h)")
    return 0


def cmd_sim_assign_ips(a) -> int:
    mix = None
    if a.mix:
        import yaml
        mix = [(m["asn"], float(m["share"]), int(m["networks"])) for m in yaml.safe_load(open(a.mix))]
    n = sim.write(sim.assign_ips(sim.read(a.base), mix, a.seed), a.out)
    print(f"wrote {n:,} rows to {a.out}")
    return 0


def cmd_sim_import(a) -> int:
    import yaml
    rows, companion = sim.import_log(a.log, a.mapping)
    n = sim.write(rows, a.out)
    mpath = a.mapping_out or str(a.out).rsplit(".", 1)[0] + ".mapping.yaml"
    with open(mpath, "w", encoding="utf-8") as fh:
        yaml.safe_dump(companion, fh, sort_keys=False)
    print(f"wrote {n:,} rows to {a.out} and its replay mapping to {mpath}")
    return 0


def cmd_prune(a) -> int:
    from .sql import SqlAudit
    n = SqlAudit(a.sql, create=False).prune(a.days)
    print(f"deleted {n['otp_events']:,} decisions and {n['alerts']:,} alerts older than {a.days} days")
    return 0


def cmd_serve(a) -> int:
    import uvicorn

    from .sentinel import Sentinel
    from .server import create_app
    g = Sentinel.from_config(a.policy, redis_url=a.redis, sql_url=a.sql, asn_tsv=a.asn) if a.policy \
        else Sentinel(Policy())
    uvicorn.run(create_app(g, show_reasons=a.show_reasons), host=a.host, port=a.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="otpguard")
    ap.add_argument("--version", action="version", version=f"otpguard {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="run one request through a policy")
    c.add_argument("--policy")
    c.add_argument("--phone", required=True)
    c.add_argument("--purpose", default="login")
    c.add_argument("--ip")
    c.set_defaults(fn=cmd_check)

    v = sub.add_parser("validate", help="load a policy file and report problems")
    v.add_argument("policy")
    v.set_defaults(fn=cmd_validate)

    r = sub.add_parser("replay", help="replay a historical log")
    r.add_argument("log")
    r.add_argument("--mapping", required=True)
    r.add_argument("--policy")
    r.add_argument("--incidents")
    r.add_argument("--out", default="replay-report")
    r.add_argument("--decisions", help="also write one line per decision to this CSV")
    r.add_argument("--shadow", action="store_true",
                   help="count every request as sent (default: blocked ones are not sent)")
    r.add_argument("--progress", type=int, default=0, metavar="N")
    r.set_defaults(fn=cmd_replay)

    s = sub.add_parser("simulate", help="synthetic traffic and attacks")
    ss = s.add_subparsers(dest="what", required=True)
    b = ss.add_parser("baseline")
    b.add_argument("--days", type=int, default=28)
    b.add_argument("--start", default="2026-01-05")
    b.add_argument("--rate", type=float, default=400, help="average OTPs per hour")
    b.add_argument("--surge", nargs=3, metavar=("START", "END", "FACTOR"))
    b.add_argument("--seed", type=int, default=1)
    b.add_argument("--out", required=True)
    b.set_defaults(fn=cmd_sim_baseline)
    i = ss.add_parser("inject")
    i.add_argument("--base", required=True)
    i.add_argument("--scenario", required=True, choices=sorted(sim.SCENARIOS))
    i.add_argument("--start", required=True)
    i.add_argument("--hours", type=float)
    i.add_argument("--rate", type=float, help="attack requests per hour")
    i.add_argument("--volume", type=float,
                   help="attack rate as a fraction of the log's mean OTP rate (overrides --rate)")
    i.add_argument("--otp-types", help="comma-separated types that are OTPs in --base (default otp:*)")
    i.add_argument("--customer-types",
                   help="comma-separated types that mark customers, for A5 (default event:*)")
    i.add_argument("--seed", type=int, default=7)
    i.add_argument("--out", required=True)
    i.set_defaults(fn=cmd_sim_inject)
    im = ss.add_parser("import", help="convert a real log to the simulator schema, to inject attacks into it")
    im.add_argument("log")
    im.add_argument("--mapping", required=True)
    im.add_argument("--out", required=True)
    im.add_argument("--mapping-out", help="where to write the replay mapping (default: next to --out)")
    im.set_defaults(fn=cmd_sim_import)
    ai = ss.add_parser("assign-ips", help="give a log without addresses synthetic ones (for A2 / D8 / D9)")
    ai.add_argument("--base", required=True)
    ai.add_argument("--mix", help="YAML list of {asn, share, networks}")
    ai.add_argument("--seed", type=int, default=11)
    ai.add_argument("--out", required=True)
    ai.set_defaults(fn=cmd_sim_assign_ips)

    pr = sub.add_parser("prune", help="delete audit rows older than the retention period")
    pr.add_argument("--sql", required=True)
    pr.add_argument("--days", type=int, default=90)
    pr.set_defaults(fn=cmd_prune)

    sv = sub.add_parser("serve", help="run the HTTP service")
    sv.add_argument("--policy")
    sv.add_argument("--redis")
    sv.add_argument("--sql")
    sv.add_argument("--asn", help="iptoasn.com TSV file")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8080)
    sv.add_argument("--show-reasons", action="store_true")
    sv.set_defaults(fn=cmd_serve)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
