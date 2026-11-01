# Research evaluation plan and current evidence

Status: the engine, the synthetic demo and the micro-benchmarks exist. **No evaluation on real environments or historical exploitation data has been performed.** Nothing here claims predictive accuracy or real-world breach prevention.

## 1. Research question

Given limited remediation capacity, incomplete and possibly contradictory evidence, and a graph of connectivity and exploit preconditions, which remediation actions most robustly reduce *modelled* feasible attacker paths to critical assets?

## 2. Threat model and permitted evidence

- Attacker: external, starts at declared entry points, moves along recorded network/trust edges by satisfying structured preconditions of recorded findings. Capabilities are abstract states.
- Evidence allowed: asset inventory, scanner findings with applicability reviews, firewall/ACL or architecture exports (topology), reviewed advisories/claims, structured preconditions, public KEV/EPSS. **Not used or required:** WAF/IDS/SIEM/EDR logs, packet captures, credentials, live scanning, exploit execution.
- Out of scope: zero-days absent from findings, unrecorded edges, insider threat, social engineering, defensive controls that are not modelled.

## 3. Hypotheses and how they could be falsified

| # | Hypothesis | Falsified if |
|---|---|---|
| H1 | Under equal effort budgets, a combined-effect graph optimiser leaves fewer weighted modelled paths than CVSS-, EPSS-, KEV-first or criticality rankings | On a representative corpus of graphs, the median gap is ≤0 or not significant |
| H2 | Provenance-aware path states change the recommendation in a non-trivial share of cases versus graph-only optimisation | `graph_only` and the provenance-aware optimum agree in (almost) all cases with real evidence churn |
| H3 | Single-factor robustness analysis identifies, *before* the change happens, the evidence whose retraction would flip the recommendation | Later retractions/corrections flip recommendations that the analysis had marked stable |
| H4 | The recommendation is stable to plausible edge-unknown perturbations in most real topologies | High flip rates under `reachability_unknown` across real graphs (that would itself be a finding: the method then mostly signals missing data) |

## 4. Datasets

| Dataset | Provenance | Status |
|---|---|---|
| `attack-path` demo (7 assets, 7 findings, 10 actions) | Synthetic, hand-authored, labelled | Shipped; used for behaviour tests only |
| Random graphs in `tests/unit/test_remediation.py` (seeded) | Synthetic | Exactness checks only |
| Benchmark generator `scripts/benchmark_v2.py` (seeded) | Synthetic | Runtime only |
| Real organisational topologies | Would need consent and anonymisation | **Not available** |
| Time-split exploitation history (KEV additions vs earlier EPSS/advisories) | Public | **Not done**; required before any predictive claim |

Synthetic data are never presented as observations. If parameters (weights, caps) are tuned, tuning, selection and evaluation data must be separated.

## 5. Baselines (equal budget)

All methods get the same integer budget, the same action catalogue, the same dependency/conflict/downtime constraints, and are scored by the same evaluator: `cvss_desc`, `epss_desc`, `kev_first`, `criticality_exposure` (greedy fill in ranking order; missing signals ranked last and disclosed), and `graph_only` (exact optimiser with provenance ignored). Coverage differs: CVSS is optional per vulnerability; EPSS/KEV exist only for imported records; enablers and edge actions have no CVSS.

## 6. Metrics and limitations

- Weighted remaining modelled paths (`weighted-paths`) and number of reachable objectives (`reachable-targets`). Both are proxies: path counts grow with graph granularity, and enumeration caps make counts lower bounds (reported as truncation).
- Effort used (integer units from the catalogue; not calibrated).
- Robustness: number of constructed single-factor scenarios in which the recommendation changes (**not a probability**), plus the uncovered multi-factor combinations.
- Runtime and peak Python heap (see §8). Exactness: exact for ≤16 eligible actions; greedy above (gap unknown in general, ≥0 by construction and checked against exact on small random graphs).

## 7. Ablations (planned; the switches exist)

| Ablation | How |
|---|---|
| No AI | Default. Hypotheses are rule-based and never change paths. External candidates can only be verified, so results with and without AI are identical by construction (tested) |
| No provenance | `graph_only` baseline |
| No graph | `cvss_desc` / `kev_first` / `epss_desc` / `criticality_exposure` |
| No robustness | `tiw triage optimize` alone vs `tiw triage robustness` |

## 8. Measured results (synthetic only)

Demo, budget 2, `weighted-paths` (lower is better), before any action 17:

| Method | Portfolio | Value |
|---|---|---|
| graph-aware exact | A-patch-api | **2** |
| graph_only | A-patch-api | 2 |
| cvss_desc | A-patch-vpn + A-patch-web | 5 |
| kev_first | A-patch-sftp + A-patch-web | 5 |
| criticality_exposure | A-patch-hr + A-rotate-svc | 9 |
| epss_desc | A-patch-admin + A-patch-sftp | 10 |

After the step-2 retraction, the provenance-aware optimum moves to `A-patch-vpn + A-patch-web` (12 → 0, two SFTP paths excluded as insufficient evidence). `graph_only` stays at `A-patch-api`, which leaves 2 under the provenance-aware evaluation. This is one hand-built example that **illustrates** H1/H2. It is not evidence for them.

Benchmark (`uv run python scripts/benchmark_v2.py --repeats 20 --seed 1`, 2026-11-01, Windows 11, Python 3.12.10, AMD64 Family 23 Model 104 laptop CPU; timings measured with tracemalloc active, which slows Python code):

| Case | Stage | Size | Result | p50 ms | p95 ms | Peak heap MB |
|---|---|---|---|---|---|---|
| small (demo) | enumerate | 8 nodes, 7 findings | 7 paths, not truncated | 3.0 | 3.7 | 0.04 |
| small (demo) | optimize exact | 10 actions, 1024 subsets | value 2 | 61.1 | 75.8 | 0.02 |
| medium | enumerate | 101 nodes, 500 findings | 2000 paths, **truncated at the 2000-path cap** | 2415.9 | 2605.4 | 5.88 |
| medium | optimize greedy | 40 actions | 1064 → 460 (on the truncated set) | 1498.5 | 1656.0 | 0.29 |
| limit | enumerate | 101 nodes, 500 findings, dense | 500 paths, truncated: path limit reported | 353.2 | 369.4 | 1.54 |

The medium case is truncated, so its objective values are lower bounds. The medium p50/p95 come from 5 repetitions and the limit case from 3. One machine only; not a formal benchmark.

## 9. Limitations and expected reviewer objections

- **Incomplete reachability maps.** Missing edges cause silent under-counting. Mitigation: explicit `unknown` edges, inclusion bounds, truncation reporting. Not solved.
- **Unverified preconditions.** Conditions are analyst-authored; errors propagate. They are shown with evidence and review state.
- **Synthetic ground truth.** The demo is constructed to exhibit a choke point; it proves the mechanism, not prevalence.
- **Path counting as an objective.** Counts depend on modelling granularity; two near-duplicate routes count twice. `reachable-targets` is provided as a coarser check.
- **Adversarial uncertainty.** A poisoned but reviewed claim is trusted until reviewed otherwise; robustness analysis shows the dependency but does not detect the poisoning.
- **Single-factor scenarios.** Interactions between two withdrawals are not enumerated; the number of uncovered combinations is reported.
- **No measured real-world breach prevention.** None claimed.
