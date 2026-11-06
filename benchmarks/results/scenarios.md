| scenario | injected | recall | precision | F1 | false-positive rate | main detectors |
|---|---|---|---|---|---|---|
| A1 pumping to one foreign country from a few IPs | 777 | 0.9768 | 0.9706 | 0.9737 | 0.0001 | D5 |
| A2 A1 with a fresh IP for every request | 672 | 0.9732 | 0.966 | 0.9696 | 0.0001 | D5 |
| A3 fresh numbers drawn sequentially from one prefix | 590 | 0.9492 | 1.0 | 0.9739 | 0.0 | D6, D8 |
| A4 low and slow: a few percent above normal for days | 1,042 | 0.072 | 0.6356 | 0.1293 | 0.00019 | D5 |
| A5 one password reset to each of many existing customers, evenly paced | 3,602 | 0.9914 | 0.9881 | 0.9897 | 0.00019 | D11, D8, D7 |
| A6 repeated resends to the same numbers without verification | 692 | 0.9798 | 1.0 | 0.9898 | 0.0 | D8 |
| A7 A1 during a legitimate traffic surge | 777 | 0.9884 | 0.8951 | 0.9394 | 0.00031 | D5, D6 |
