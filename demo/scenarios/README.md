# Demo scenarios

The synthetic fixtures live inside the package at `src/tiw/demo_data/` so that an installed wheel can run the demo. Each scenario directory holds the files applied step by step by `tiw demo seed` / `tiw demo advance`; the step list and fixed clock values are defined in `src/tiw/services/demo.py`.

| Directory | Scenario |
|---|---|
| `escalation/` | A: intelligence changes the remediation decision |
| `amplification/` | B: more articles, no more evidence |
| `expiry/` | C: the basis for deferral breaks |
| `correction/` | D: correction is not the same as an outage |

All records are self-authored, marked `"synthetic": true`, and use `DEMO-VULN-###` identifiers. `correction/kev-broken.json` is deliberately truncated to simulate a failed feed retrieval.
