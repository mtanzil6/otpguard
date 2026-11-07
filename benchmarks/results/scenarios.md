Seeds: [1, 2, 3]; volumes (fraction of legitimate OTP rate, None = scenario default): [None]. Mean [95 % interval] over seeds.

| scenario | volume | design | injected | recall | precision | F1 | FPR | customer collateral | main detectors |
|---|---|---|---|---|---|---|---|---|---|
| A1 pumping to one foreign country from a few IPs | default | full | 737 | 0.977 [0.975, 0.979] | 0.959 [0.947, 0.972] | 0.968 [0.961, 0.975] | 0.00013 [0.00009, 0.00017] | 0.00014 [0.00010, 0.00019] | D5, D6 |
| A1 pumping to one foreign country from a few IPs | default | limiter | 737 | 0.026 [0.016, 0.036] | 1.000 | 0.051 [0.031, 0.070] | 0.00000 | 0.00000 | D1, D8 |
| A2 A1 with a fresh IP for every request | default | full | 698 | 0.975 [0.973, 0.978] | 0.958 [0.946, 0.969] | 0.966 [0.960, 0.972] | 0.00013 [0.00009, 0.00017] | 0.00014 [0.00010, 0.00019] | D5, D6 |
| A2 A1 with a fresh IP for every request | default | limiter | 698 | 0.015 [0.009, 0.021] | 1.000 | 0.029 [0.017, 0.041] | 0.00000 | 0.00000 | D1 |
| A3 fresh numbers drawn sequentially from one prefix | default | full | 589 | 0.955 [0.934, 0.976] | 0.999 [0.998, 1.000] | 0.977 [0.966, 0.987] | 0.00000 | 0.00000 | D8, D6 |
| A3 fresh numbers drawn sequentially from one prefix | default | limiter | 589 | 0.000 | – | – | 0.00000 | 0.00000 |  |
| A4 low and slow: a few percent above normal for days | default | full | 987 | 0.051 [0.031, 0.072] | 0.624 [0.581, 0.668] | 0.095 [0.060, 0.129] | 0.00013 [0.00008, 0.00019] | 0.00013 [0.00006, 0.00021] | D5, D6 |
| A4 low and slow: a few percent above normal for days | default | limiter | 987 | 0.000 | – | – | 0.00000 | 0.00000 |  |
| A5 one password reset to each of many existing customers, evenly paced | default | full | 3,611 | 0.992 | 0.991 [0.988, 0.994] | 0.991 [0.990, 0.993] | 0.00014 [0.00009, 0.00018] | 0.00006 [0.00002, 0.00010] | D8, D11, D7 |
| A5 one password reset to each of many existing customers, evenly paced | default | limiter | 3,611 | 0.000 | – | – | 0.00000 | 0.00000 |  |
| A6 repeated resends to the same numbers without verification | default | full | 676 | 0.979 [0.979, 0.980] | 0.999 [0.998, 1.000] | 0.989 [0.989, 0.990] | 0.00000 | 0.00000 | D8, D6 |
| A6 repeated resends to the same numbers without verification | default | limiter | 676 | 0.985 | 1.000 | 0.993 | 0.00000 | 0.00000 | D8 |
| A7 A1 during a legitimate traffic surge | default | full | 737 | 0.980 [0.971, 0.989] | 0.896 [0.860, 0.931] | 0.936 [0.918, 0.954] | 0.00029 [0.00019, 0.00039] | 0.00029 [0.00020, 0.00037] | D5, D6 |
| A7 A1 during a legitimate traffic surge | default | limiter | 737 | 0.026 [0.016, 0.036] | 1.000 | 0.051 [0.031, 0.070] | 0.00000 | 0.00000 | D1, D8 |
