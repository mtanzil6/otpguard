# Reproducing the manuscript's evaluation (Tables 7–9)

The case-study log is not public. These are the commands the authors run on it; on
your own log they produce the same tables for your service. Edit
`examples/mapping-case-study.yaml` (column names, message types) and
`examples/incidents-case-study.yaml` (the ten I2 burst days) first.

## Table 7: replay on the case-study log

```bash
# full policy
otpguard replay sms_log.csv --mapping examples/mapping-case-study.yaml \
    --policy examples/policy.yaml --incidents examples/incidents-case-study.yaml \
    --out results/replay-full --progress 200000

# conventional limiter and layer ablations: the same command with a policy where
# the corresponding detectors are disabled (see design_policy() in
# benchmarks/run_scenarios.py), e.g. without the population layer:
#   detectors: {D5: {enabled: false}, D6: {enabled: false}, D7: {enabled: false},
#               D8: {enabled: false}, D9: {enabled: false}, D10: {enabled: false},
#               D11: {enabled: false}}
```

Read from `replay.json`: `incidents.I1.first_flag_after_h` (delay),
`incidents.I1.excess_stopped` and `incidents.I2.*.excess_stopped` (coverage), and
`collateral.legitimate_windows.S1..S3.rate`. The log has no IP addresses, so the
limiter reduces to its per-number caps there; say so in the table note.

## Table 8: simulated attacks injected into the log

```bash
otpguard simulate import sms_log.csv --mapping examples/mapping-case-study.yaml --out base.csv
otpguard simulate assign-ips --base base.csv --mix examples/asn-mix.yaml --out base_ip.csv
python benchmarks/run_scenarios.py --base base_ip.csv --mapping base.mapping.yaml \
    --attack-at 2022-05-10T10:00 --seeds 10 --volumes 0.01 0.05 0.1 0.2 \
    --designs full limiter --out results/simulation
```

`--attack-at` and `simulate inject --start` are read as UTC (imported timestamps are
epoch seconds). A7 needs a legitimate surge: pass `--attack-at` inside S3 (e.g. `2022-04-20T10:00`) and
`--only A7`. A5 draws its targets from numbers that received a shipping message.

## Table 9: latency

```bash
redis-server --port 6379 --save "" &
python benchmarks/latency.py --n 50000 --redis redis://localhost:6379/1 \
    --out results/latency.json
```

State the machine (the JSON records it). A decision makes several Redis round trips;
only the hard rules (D1, D12) are atomic.
