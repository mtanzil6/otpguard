# Changelog

## 0.1.0 (2026-11-08)

- Twelve detectors in four layers (request, history, population, budget)
- Weighted noisy-OR scoring with hard rules and per-purpose / per-country policy
- Memory and Redis stores; SQL audit trail with grouped alerts
- Shadow mode, fail-open / fail-closed
- HTTP service (`otpguard serve`) and `AsyncSentinel` for asyncio apps
- Log replay (CSV or JSON Lines, gzipped or not) with labelled windows and customer collateral
- Synthetic traffic and attack scenarios A1–A7; import of real logs for injection

### Changes during review (before release)

- Hard rules are atomic: `Store.reserve` checks every window and increments in one
  step (one Lua script on Redis). D1 caps and D12 budgets use it; a request blocked by
  another detector gives its reservations back.
- D12: daily budgets per country, and hourly / daily budgets over all countries
  (`budget: {per_hour, per_day}`). Home countries without their own rule now take the
  default price, so total budgets count home spend.
- D5 also requires the count behind a share shift to be unlikely under Poisson
  (`p_value`, default 1e-3), which keeps small countries quiet.
- D7 keeps a second series per purpose and destination country, so pacing into one
  foreign country is visible under busy home traffic.
- D8 `hard_cap` turns the per-IP limit into a block (conventional-limiter baseline).
- `timezone` in the policy (campaign dates) and in the replay mapping (naive timestamps).
- Replay mapping: `customer_events` separates the customer proxy used for collateral
  from the event types D11 reads; the report flags it when they coincide.
- `report_event(..., phone=)` is used; the HTTP `/v1/event` accepts `phone`.
- Store sets replace JSON lists for the per-hour "active keys" (O(1) per add on Redis).
- `MemoryStore`: values set before the first counter write no longer expire at once.
- `otpguard prune` deletes audit rows past the retention period.
- `otpguard simulate import` / `assign-ips` and `inject --volume` for injecting
  attacks into a real log; `benchmarks/run_scenarios.py` runs several seeds, attack
  volumes, a limiter baseline and layer ablations; `benchmarks/latency.py`.
- Tests for D4, D5, D6, D7, D9, D11, D12, baselines, reservations under concurrency
  (memory, fakeredis and a real Redis in CI), and import → inject → replay.
