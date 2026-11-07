# otpguard

Decide whether an OTP SMS should go out before you pay for it.

`otpguard` sits between your app and your SMS provider. You call `check()` before
sending a one-time password; it answers **allow**, **challenge** or **block**, with the
reasons. It is aimed at SMS pumping (artificially inflated traffic), SMS bombing and
account enumeration through the password-reset flow.

It works with any SMS provider and any framework (there is an HTTP service for
non-Python apps), and it does not rely on the client IP: most checks look at where the
messages are going and at the shape of the traffic, which attackers can't rotate as
cheaply as addresses.

## Install

```bash
pip install git+https://github.com/mtanzil6/otpguard.git                    # core, in-memory store
pip install "otpguard[redis,sql] @ git+https://github.com/mtanzil6/otpguard.git"  # shared state in Redis, audit trail in SQL
pip install "otpguard[server] @ git+https://github.com/mtanzil6/otpguard.git"     # HTTP service
```

Not yet on PyPI — install straight from GitHub. Python 3.10+.

## Use

```python
from otpguard import OtpRequest, Sentinel

guard = Sentinel.from_config("policy.yaml",
                             redis_url="redis://localhost:6379/0",
                             sql_url="postgresql://otp@db/otp")

d = guard.check(OtpRequest(phone="+966512345678", purpose="register",
                           ip=client_ip, session_id=sid, session_age_ms=age))
if d.allowed:
    provider.send(phone, code)
elif d.action == "challenge":
    ...  # CAPTCHA, then check again with challenge_passed=True
else:
    ...  # generic error, wait d.retry_after seconds

# later, when the user types the right code
guard.report_verified(d.request_id)
```

`d.allowed` is always `True` in shadow mode, so you can run it in production and
watch what it would have done before you let it block anything.

Feedback makes it much better. `report_verified()` feeds the verification-ratio and
resend checks; `report_event("order", ts)` (or logins, or whatever should follow an
OTP) feeds the conversion check.

For asyncio apps, `AsyncSentinel.from_config(...)` has the same methods as coroutines.

### HTTP

```bash
otpguard serve --policy policy.yaml --redis redis://localhost:6379/0 --port 8080
```

```
POST /v1/check     {"phone": "...", "purpose": "login", "ip": "..."}  -> {"action": "allow", "allowed": true, "request_id": "...", ...}
POST /v1/sent      {"request_id": "...", "cost": 0.04}
POST /v1/verified  {"request_id": "..."}
POST /v1/event     {"kind": "order", "phone": "..."}
GET  /health
```

Reasons are not returned to the client unless you start the server with
`--show-reasons`; they go to the SQL audit log.

## What it checks

| | detector | looks at |
|---|---|---|
| D1 | purpose cap | codes per number per purpose, 1 h and 24 h (hard block) |
| D2 | destination risk | country / number-range rules from the policy |
| D3 | resend without verify | several codes to one number, none entered |
| D4 | verification ratio | share of codes entered, per country and purpose |
| D5 | country share | a country's share of traffic against its usual share for that hour of the week |
| D6 | prefix burst | never-seen numbers piling up in one number range |
| D7 | pacing | requests arriving at a steady, machine-like pace |
| D8 | network concentration | requests per IP, /24 (/48), ASN; hosting networks |
| D9 | IP rotation | far more never-seen IPs than usual in a country/purpose bucket |
| D10 | client integrity | session token age and reuse, device attestation |
| D11 | conversion mismatch | e.g. password resets rising while logins don't |
| D12 | spend budget | spend per country and in total, per hour and per day (challenge, then block) |

Each detector returns a score between 0 and 1. Scores are combined with a weighted
noisy-OR (`risk = 1 - Π(1 - wᵢ·sᵢ)`); hard rules (caps, deny lists, exhausted budgets)
set a floor. Thresholds, weights, caps, country rules and budgets all live in the
policy file, see [`examples/policy.yaml`](examples/policy.yaml).

D8–D10 only run when you pass an IP or session data. Nothing breaks without them.

## Storage

- **Redis** for live counters (1-minute and 1-hour buckets, HyperLogLog for distinct
  IPs). Shared by all app servers. The hard rules (per-number caps, spend budgets) are
  checked and taken in one Lua script, so concurrent requests on different servers
  cannot pass a cap together; the other detectors read counters with plain MGETs.
- **SQL** (anything SQLAlchemy supports) for the audit trail: one row per decision,
  outcomes, policy versions and grouped alerts. `otpguard prune --sql URL --days 90`
  deletes old rows (run it from cron).
- **Memory** for tests, replay and single-process setups.

Phone numbers are stored only as an HMAC under your secret (`OTPGUARD_SECRET`);
only the country code and a short prefix are kept in clear. IPs are kept as their
network.

If Redis is unreachable, `fail_mode: open` keeps serving with per-process limits;
`closed` blocks.

## Replay your own logs

Most teams already have an SMS log with a timestamp, a number and a message type.
That is enough to see what a policy would have done:

```bash
otpguard replay sms_log.csv --mapping mapping.yaml --policy policy.yaml \
    --incidents incidents.yaml --out report/
```

The log can be CSV or JSON Lines, optionally gzipped. The mapping file says which
columns to read, the time zone of the timestamps, which message types are OTPs (and for
which purpose), which are follow-up events for D11 (`events`) and which mark a real
customer for the collateral figure (`customer_events`; keep these different from
`events`, or D11 is graded on its own input). See
[`examples/mapping-case-study.yaml`](examples/mapping-case-study.yaml) and
[`examples/incidents-case-study.yaml`](examples/incidents-case-study.yaml). The report lists
what would have been challenged or blocked, per day and per detector, how many likely
customers (numbers that got an order or delivery message within a week) were caught,
and, for windows you label in the incidents file, how quickly and how much was caught.

## Simulate attacks

```bash
otpguard simulate baseline --days 28 --out base.csv
otpguard simulate inject --base base.csv --scenario A2 --start 2026-01-26T10:00 --out mixed.csv
otpguard replay mixed.csv --mapping examples/mapping-synthetic.yaml --policy examples/policy.yaml
```

To inject attacks into your own log instead of synthetic traffic:

```bash
otpguard simulate import sms_log.csv --mapping mapping.yaml --out base.csv   # also writes base.mapping.yaml
otpguard simulate assign-ips --base base.csv --mix examples/asn-mix.yaml --out base_ip.csv   # optional, for A2/D8/D9
otpguard simulate inject --base base_ip.csv --scenario A2 --start 2022-05-10T10:00 --volume 0.05 --out mixed.csv
otpguard replay mixed.csv --mapping base.mapping.yaml --policy policy.yaml
```

`--volume` sets the attack rate as a fraction of the log's average OTP rate.

Scenarios: A1 pumping to one country from a few IPs, A2 the same with a fresh IP per
request, A3 sequential numbers from one prefix, A4 low and slow, A5 one reset to each of
many existing customers, A6 resend loops, A7 A1 during a sale.
`python benchmarks/run_scenarios.py` runs all of them; add `--seeds 10`, `--volumes 0.01
0.05 0.1 0.2`, `--designs full limiter without-L1 without-L3 without-L4` (a conventional
per-number + per-IP limiter and layer ablations) and `--base`/`--mapping` for your own
imported log. `python benchmarks/latency.py --redis redis://localhost:6379/1` measures
decision latency. Results from the current version are in
[`benchmarks/results`](benchmarks/results/scenarios.md). They come from synthetic
traffic, so treat them as a sanity check rather than a promise.

## Limits

- A decision makes several Redis round trips (one per counter family); only the hard
  rules are atomic. Soft scores can be off by a request or two under heavy concurrency.
- Baselines need a few days of traffic. Until then the caps, country rules and
  budgets do most of the work.
- An attacker who spreads traffic thinly over many countries, each below its usual
  share, is mostly stopped by the budgets, not by detection.
- Set `timezone` in the mapping and the policy to the zone your log is written in;
  naive timestamps and campaign dates are read in that zone.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
