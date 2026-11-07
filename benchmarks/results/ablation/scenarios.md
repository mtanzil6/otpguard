Seeds: [1]; volumes (fraction of legitimate OTP rate, None = scenario default): [None]. Mean [95 % interval] over seeds.

| scenario | volume | design | injected | recall | precision | F1 | FPR | customer collateral | main detectors |
|---|---|---|---|---|---|---|---|---|---|
| A1 pumping to one foreign country from a few IPs | default | without-L1 | 777 | 0.977 | 0.971 | 0.974 | 0.00010 | 0.00010 | D5 |
| A1 pumping to one foreign country from a few IPs | default | without-L2 | 777 | 0.977 | 0.971 | 0.974 | 0.00010 | 0.00010 | D5 |
| A1 pumping to one foreign country from a few IPs | default | without-L3 | 777 | 0.255 | 0.990 | 0.405 | 0.00001 | 0.00001 | D12, D1 |
| A1 pumping to one foreign country from a few IPs | default | without-L4 | 777 | 0.977 | 0.971 | 0.974 | 0.00010 | 0.00010 | D5 |
| A2 A1 with a fresh IP for every request | default | without-L1 | 672 | 0.973 | 0.966 | 0.970 | 0.00010 | 0.00010 | D5 |
| A2 A1 with a fresh IP for every request | default | without-L2 | 672 | 0.973 | 0.966 | 0.970 | 0.00010 | 0.00010 | D5 |
| A2 A1 with a fresh IP for every request | default | without-L3 | 672 | 0.149 | 0.962 | 0.258 | 0.00002 | 0.00001 | D12, D1 |
| A2 A1 with a fresh IP for every request | default | without-L4 | 672 | 0.973 | 0.966 | 0.970 | 0.00010 | 0.00010 | D5 |
| A3 fresh numbers drawn sequentially from one prefix | default | without-L1 | 590 | 0.890 | 1.000 | 0.942 | 0.00000 | 0.00000 | D6, D8 |
| A3 fresh numbers drawn sequentially from one prefix | default | without-L2 | 590 | 0.949 | 1.000 | 0.974 | 0.00000 | 0.00000 | D6, D8 |
| A3 fresh numbers drawn sequentially from one prefix | default | without-L3 | 590 | 0.661 | 1.000 | 0.796 | 0.00000 | 0.00000 | D12 |
| A3 fresh numbers drawn sequentially from one prefix | default | without-L4 | 590 | 0.949 | 1.000 | 0.974 | 0.00000 | 0.00000 | D6, D8 |
| A4 low and slow: a few percent above normal for days | default | without-L1 | 1,042 | 0.053 | 0.632 | 0.097 | 0.00014 | 0.00014 | D5 |
| A4 low and slow: a few percent above normal for days | default | without-L2 | 1,042 | 0.072 | 0.636 | 0.129 | 0.00019 | 0.00021 | D5 |
| A4 low and slow: a few percent above normal for days | default | without-L3 | 1,042 | 0.000 | – | – | 0.00000 | 0.00000 |  |
| A4 low and slow: a few percent above normal for days | default | without-L4 | 1,042 | 0.072 | 0.636 | 0.129 | 0.00019 | 0.00021 | D5 |
| A5 one password reset to each of many existing customers, evenly paced | default | without-L1 | 3,602 | 0.992 | 0.988 | 0.990 | 0.00018 | 0.00005 | D8, D11, D7 |
| A5 one password reset to each of many existing customers, evenly paced | default | without-L2 | 3,602 | 0.992 | 0.988 | 0.990 | 0.00018 | 0.00005 | D8, D11, D7 |
| A5 one password reset to each of many existing customers, evenly paced | default | without-L3 | 3,602 | 0.000 | – | – | 0.00000 | 0.00000 |  |
| A5 one password reset to each of many existing customers, evenly paced | default | without-L4 | 3,602 | 0.992 | 0.988 | 0.990 | 0.00018 | 0.00005 | D8, D11, D7 |
| A6 repeated resends to the same numbers without verification | default | without-L1 | 692 | 0.980 | 1.000 | 0.990 | 0.00000 | 0.00000 | D8 |
| A6 repeated resends to the same numbers without verification | default | without-L2 | 692 | 0.980 | 1.000 | 0.990 | 0.00000 | 0.00000 | D8 |
| A6 repeated resends to the same numbers without verification | default | without-L3 | 692 | 0.740 | 1.000 | 0.851 | 0.00000 | 0.00000 | D1 |
| A6 repeated resends to the same numbers without verification | default | without-L4 | 692 | 0.980 | 1.000 | 0.990 | 0.00000 | 0.00000 | D8 |
| A7 A1 during a legitimate traffic surge | default | without-L1 | 777 | 0.985 | 0.896 | 0.938 | 0.00030 | 0.00035 | D5, D6 |
| A7 A1 during a legitimate traffic surge | default | without-L2 | 777 | 0.988 | 0.895 | 0.939 | 0.00031 | 0.00035 | D5, D6 |
| A7 A1 during a legitimate traffic surge | default | without-L3 | 777 | 0.302 | 0.922 | 0.455 | 0.00007 | 0.00008 | D12 |
| A7 A1 during a legitimate traffic surge | default | without-L4 | 777 | 0.988 | 0.895 | 0.939 | 0.00031 | 0.00035 | D5, D6 |
