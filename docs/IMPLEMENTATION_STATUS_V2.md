# Implementation status: v2 (attack-path triage)

Branch `feat/evidence-grounded-attack-path-triage`. Legend: `[x]` done and covered by automated tests or a recorded manual check; `[ ]` not done; `[~]` partly done (see note).
Last updated: 2026-11-01. Baseline before v2: 123 tests passing. Now: **226 passed** (`uv run pytest`), 0 failed.

## M1: offline attack graph (P0)

- [x] Reuses imported assets/findings/applicability; new `topology` and `exploit_conditions` imports with source revisions, `graph_inputs` versions and whole-file rollback
- [x] Graph-evidence claims (`reachability`, `precondition`) through the existing claims ledger (reviews, retractions, supersedes)
- [x] Fact resolution (satisfied / unknown / unsupported / disputed / refuted), path states (supported / conditional / insufficient_evidence / contradicted), refuted hops blocked and listed
- [x] Bounded DFS (hops, paths, expansions, node/edge limits) with truncation reasons; simple paths only (cycles safe); deterministic ids and order
- [x] CLI `tiw graph build|explain|hypotheses`; REST `GET /api/v1/graph`, `POST /api/v1/graph/build`, `GET /api/v1/graph/paths/{id}`; UI Attack Paths + Evidence Inspector
- [x] No WAF/IDS/SIEM input anywhere in the v2 flow (test asserts zero observations / sensor windows)

## M2: counterfactual triage (P0)

- [x] `remediations` import (integer effort, downtime, requires, conflict groups, verification status); validation of references, cycles, costs
- [x] Removal-only effect simulation; combined effect of a set; re-simulation of the chosen portfolio
- [x] Exact optimiser (≤16 eligible actions) with deterministic tie-breaking, ties, alternatives and infeasibility examples; labelled greedy above (checked ≥ exact on random small graphs)
- [x] Two objectives (`weighted-paths`, `reachable-targets`), configured weights
- [x] Equal-budget baselines: CVSS, EPSS, KEV-first, criticality/exposure, graph-only
- [x] Remediation Lab UI with evidence-linked reasons, baseline comparison, before/after, residual and excluded paths

## M3: robustness (P0)

- [x] Scenarios: withdraw claim, reachability unknown, applicability unknown, stale clock, pessimistic/optimistic bounds; caps and uncovered counts
- [x] Flip explanations down to fact and evidence ids; "k/n scenarios (not a probability)"
- [x] Append-only `analysis_runs` with evidence hash, previous run and decision diff; identical results not duplicated
- [x] Demo step 2 (retraction) changes the preferred portfolio; diff names the retracted claim
- [x] Interactive what-if on the Robustness page (GET, nothing stored)

## M4: offline agentic hypotheses (P1)

- [x] Deterministic rule-based generator + verification against recorded facts
- [x] Strict schema/provenance gate for external candidates (file / API), injection-inert, no execution, never persisted as facts
- [~] Optional LLM adapter: only the provider protocol and a disabled provider exist. **No network LLM transport was implemented**
- [x] AI-disabled path is the default and functionally complete

## M5: Arsenal polish (P0 for presentation)

- [x] `tiw demo seed --scenario attack-path`, `tiw demo reset --yes`, UI one-click reset and step-2 buttons; A–D unchanged
- [x] Docs: `ROADMAP_V2.md`, `ARCHITECTURE_V2.md`, `DATA_FORMATS_V2.md`, `ARSENAL_DEMO.md`, `RESEARCH_EVALUATION.md`, this file; README quick start
- [x] Screenshots from the running UI (Chromium/Playwright) at 1440/768/390: no horizontal page overflow and no console errors on 6 pages × 3 widths
- [x] Benchmark script and recorded results (one laptop; medium case truncated, disclosed)
- [x] Reproducible normalized JSON across fresh workspaces (tested)
- [ ] Real-world or historical evaluation (not done; see `RESEARCH_EVALUATION.md`)

## Input burden (follow-up)

- [x] Downloadable templates for `topology`, `exploit_conditions` and `remediations` (verified to import cleanly into a live workspace together with the CSV templates)
- [x] Drafts generated from imported findings (`tiw draft …`, Import screen button, `/api/v1/drafts`): curated entries kept, missing ones appended; `service_ports: ["any"]` adds an explicit unknown fact so drafted paths stay conditional; efforts are labelled placeholders
- [x] Simplified topology input: edge CSV (`tiw import topology-csv`, Import kind `topology_csv`) and the Network Paths screen (add/delete paths, crown-jewel weights); CSV export round-trips the demo topology with identical path ids and states; converted documents go through the normal topology validation; errors are mapped to CSV lines; typos never create entry points

## Hosting

- [x] Static GitHub Pages snapshot of the synthetic demo (`scripts/build_static_demo.py`, `.github/workflows/pages.yml`): ~1,080 pre-rendered pages, link check (0 broken), browser check 19/19 (navigation, form variants, step switch, disabled POSTs, mobile overflow, no failed requests/console errors). Read-only by construction

## Design decisions and deviations

| # | Topic | Decision |
|---|---|---|
| 1 | Spec example ids `DEMO-VULN-001..003` | The demo uses `DEMO-VULN-101..107` so it cannot collide with scenarios A–D |
| 2 | Demo families | attack-path and A–D refuse to share a workspace (each ships its own synthetic KEV snapshot, which would change the other's outcomes). `--scenario all` still means A–D |
| 3 | Default inclusion | `as_recorded` counts supported + conditional + contradicted paths; `insufficient_evidence` is excluded *and listed*; bounds are available. Documented in every export |
| 4 | Exploit conditions | Per vulnerability, not per asset |
| 5 | Graph claims | Reuse the claims table with predicates `reachability`/`precondition` and subjects `edge:`/`cond:`; they never create vulnerability records or assessments |
| 6 | Container demo | `TIW_MODE=demo` now serves attack-path by default; `TIW_DEMO_SCENARIO=legacy` restores A–D |
| 7 | Navigation | v2 screens come first when a topology exists; the sensor page is labelled "Sensor events (optional)" when no telemetry exists. Legacy screens are unchanged |
| 8 | Technique ids | Format-checked only; no ATT&CK snapshot shipped; `T0000` flagged as placeholder |
| 9 | License | No LICENSE file exists, so the README no longer claims Apache-2.0; the licence is undecided |

## Not implemented

OSV/advisory import, network LLM provider, multi-factor scenario sampling, per-asset conditions, PostgreSQL, multi-user. Browser tests used Chromium only.
