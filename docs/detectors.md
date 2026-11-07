# Detector reference (v0.1.0)

Defaults are those in `src/otpsentinel/policy.py`; every value can be set per detector
in the policy file, and weights per purpose. This page is the source for the
manuscript's Tables 3 and 4; keep the three in step.

## Detectors

| ID | Layer | Detector | Rule and defaults | Needs | State (store keys) |
|---|---|---|---|---|---|
| D1 | L1 request | purpose cap | ≥ `cap_1h` codes to one number for one purpose in 60 min, or ≥ `cap_24h` in 24 h → **block** (hard rule, reserved atomically). Defaults 6 / 10 (`purposes.default`); example policy: register 5/8, login 6/10, reset 4/6 | – | `cap:{purpose}:{h}` minute+hour buckets |
| D2 | L1 request | destination risk | score = max(country `risk`, longest matching `prefixes` entry); `deny: true` or prefix risk 1.0 → **block**; unparsable number 0.5; foreign country with no rule `foreign_default_risk` 0.2 | – | none (policy) |
| D3 | L2 history | resend without verify | ≥ `k`=3 sends to one number in `window_min`=30 with none verified | `report_verified` | `snd:{h}`, `ver:{h}` |
| D4 | L2 history | verification ratio | per purpose × country over 60 min (ignoring the last 5 min of sends): posterior mean (ver + r₀·20)/(sent + 20), r₀ = learned ratio or 0.7; fires when it is > 40 % below r₀; `min_sent` 20 | `report_verified` | `snd:p:{purpose}:cc:{cc}`, `ver:p:…`; baseline `vr` |
| D5 | L3 population | country share shift | share of a foreign country in the last 60 min vs its hour-of-week EWMA; fires when ratio ≥ 2.0, share − baseline ≥ 1 pt, ≥ 20 OTPs, and Poisson tail P(X ≥ n \| baseline × total) < 1e-3; score ramps to 1 at ratio 5.0 | – | `otp:cc:{cc}`, `otp:all`; baseline `share` |
| D6 | L3 population | prefix burst | never-seen numbers in one prefix (calling code + 3 national digits) in 30 min; fires when ≥ 8 and Poisson tail < 1e-4 against the prefix's learned hourly rate (cold foreign prefix: 1/h; cold home prefix: silent) | – | `seen:{h}` (90 d), `pnew:{prefix}`, `pnewc:{prefix}`; baseline `pnew` |
| D7 | L3 population | pacing regularity | last 40 request times per purpose and per purpose × country; fires when CV of gaps ≤ 0.35 and rate ≥ 3 × the learned rate (min 5/h); the stronger series wins | – | `ts:{purpose}`, `ts:{purpose}:{cc}` (capped lists); baseline `prate` |
| D8 | L3 population | network concentration | > 10 requests per IP, > 30 per /24 (/48), > 300 per ASN in 10 min; hosting network 0.4. With `hard_cap: true` the per-IP limit blocks (used for the limiter baseline) | IP | `ip:`, `net:`, `asn:` |
| D9 | L3 population | IP rotation | per country × purpose in 15 min (≥ 30 requests): share from never-seen IPs ≥ baseline + 0.3, and distinct IPs / requests ≥ 0.9 in the current 15-min slot | IP | `seenip:{ip}` (30 d), `rot:n:`, `rot:new:`, HLL `rot:ips:{bucket}:{slot}`; baseline `newip` |
| D10 | L3 population | client integrity | failed attestation 0.9; session younger than 800 ms 0.8; token used > 5 times in 60 min 0.7; missing token 0.6 only if `require_session` | session / attestation | `sess:{id}` |
| D11 | L3 population | conversion mismatch | for purposes listed in `events`: OTPs ÷ follow-up events over 60 min ≥ 3 × the learned ratio, ≥ 50 OTPs | `report_event` | `otp:p:{purpose}`, `ev:{kind}`; baseline `conv` |
| D12 | L4 budget | spend budget | country price summed per country and in total, per hour and per day; over budget → **challenge**; over `block_factor` (2.0) × budget → **block** (reserved atomically) | prices in policy | `spend:{cc}`, `spend:all` |

During a declared campaign the volume detectors D5, D6, D7 and D11 are scaled by 0.5.
Baselines are **not** frozen during campaigns: freezing them made every planned sale
look like an attack on return to normal traffic.

A solved challenge (`challenge_passed=True`) multiplies the weights of D7–D10 by 0.3
and clears a challenge, but never a block or a hard rule.

## Scoring

risk = 1 − ∏ᵢ (1 − wᵢ · sᵢ) over the soft detectors; hard rules set a floor
(block → 1.0, challenge → the challenge threshold). allow < 0.5 ≤ challenge < 0.85 ≤ block.

## Baselines

EWMA mean and variance per dimension and key (α = 0.05), plus an hour-of-week profile
(α = min(0.5, 6α)) used once that hour has ≥ 3 observations. Updated in process when an
hour closes; a `rolled:{hour}` marker in the store makes sure only one server does it.
Sparse keys (prefixes, IP buckets, verification ratios) have no weekly profile and
decay towards zero over hours without traffic.

## Storage

Counters are kept in 1-minute buckets (3 h TTL) and 1-hour buckets (8 d TTL); windows
up to 120 min sum minute buckets, longer ones hour buckets. `Store.reserve` (D1, D12)
sums every window and increments only if all caps hold, in one Lua script on Redis.
Phone numbers appear only as `h` = HMAC-SHA256(secret, E.164), truncated to 96 bits.
