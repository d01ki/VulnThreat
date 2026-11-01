# VulnThreat 2.0 roadmap and architecture gap analysis

Scope: implement `docs/VULNTHREAT_CLAUDE_CODE_IMPLEMENTATION.md` (evidence-grounded attack-path reasoning and counterfactual patch triage, no WAF/IDS/SIEM logs) on top of the existing `tiw` workbench without removing features.

Baseline before any v2 change: branch `main` at `c9e15fc`, `uv run pytest` → **123 passed**.

## 1. What already existed (reused)

| Existing piece | Location | How v2 reuses it |
|---|---|---|
| Asset / finding CSV import, applicability reviews with expiry | `adapters/inventory.py`, `services/ingest.py` | Graph nodes are imported assets; exploit hops are imported findings; applicability becomes a graph fact (`applicability:<finding>`) |
| Import orchestration: size limits, content-addressed raw storage, idempotency by hash, whole-file rollback, `--allow-partial`, `--dry-run`, audit events | `services/ingest.py` | The three new kinds (`topology`, `exploit_conditions`, `remediations`) are ordinary adapters + writers in the same pipeline |
| Source revisions (versioned provenance) | `storage/models.py` | Each v2 input is stored as a `source_revision` and a new append-only `graph_inputs` row |
| Claims ledger: append-only reviews, retractions, `supersedes`, relation verification, `mark_inactive` | `adapters/claims.py`, `domain/claims.py`, `services/pipeline.py` | Graph evidence is a claim with predicate `reachability` or `precondition`; retraction, rejection and supersession work unchanged |
| KEV / EPSS saved-response import and allowlisted fetch | `adapters/feeds.py`, `services/fetch.py` | Used only for the comparison baselines (`kev_first`, `epss_desc`), never by the optimiser objective |
| Append-only guard (`before_update` / `before_delete` rejection) | `storage/models.py` | Extended to `graph_inputs` and `analysis_runs` |
| Alembic migrations, schema-vs-model check | `migrations/`, `storage/db.py` | New reversible revision `0002_attack_graph` |
| Fixed clock, synthetic/live workspace separation | `storage/db.py` | Demo determinism; live workspaces reject synthetic v2 inputs |
| CLI (Typer), REST `/api/v1` with bearer token and error envelope, server-rendered UI with CSP/CSRF/Host/Origin checks | `cli/`, `api/` | New `tiw graph …` / `tiw triage …`, `/api/v1/graph…`, `/api/v1/triage/…`, `/api/v1/analysis-runs…`; new screens use the same `render()` and security middleware |
| Decision diff idea (previous id, "why this changed") | `services/queries.py` | `analysis_runs.previous_id` + `run_diff()` give the same before/after explanation for portfolios |
| Demo scenarios A–D | `services/demo.py` | Kept intact (`--scenario all` still means A–D); new scenario `attack-path` |

## 2. Gaps closed by v2

| Gap | Resolution |
|---|---|
| No notion of connectivity, entry points or crown jewels | `topology.json` + `domain/attack_graph.py` (typed nodes, network/trust edges, objectives with configured weights) |
| No structured exploit preconditions | `exploit_conditions.json` (service ports, required/granted abstract capability, conditions with evidence; no payload fields accepted) |
| No path-level uncertainty | Five fact states → four path states (`supported`, `conditional`, `insufficient_evidence`, `contradicted`); refuted facts block hops |
| Per-finding decisions only | `domain/remediation.py`: combined-effect portfolio optimiser (exact ≤16 actions, labelled greedy above), equal-budget baselines |
| No sensitivity analysis | `domain/robustness.py`: single-factor counterfactual scenarios, flip explanations, bounded optimistic/pessimistic inclusion |
| No reproducible analysis records | `analysis_runs` table with evidence snapshot hash, algorithm version, params, result hash, previous run |
| Telemetry-centred UI | v2 workflow first in the navigation when a topology exists; the sensor menu entry is labelled "Sensor events (optional)" when no telemetry exists |

## 3. Milestones (status in `IMPLEMENTATION_STATUS_V2.md`)

- **M1** offline attack graph: topology/conditions import, fact resolution, bounded enumeration, CLI/API/UI.
- **M2** counterfactual triage: remediation catalog, simulator, exact optimiser, baselines, Remediation Lab.
- **M3** robustness: scenarios, flip reasons, append-only run history, retraction demo.
- **M4** deterministic hypotheses + schema gate; external candidates via file/API only (no network LLM adapter).
- **M5** demo, docs, screenshots, benchmark.

## 4. Next steps (not done)

1. Optional OSV / advisory import with explicit provenance (spec §2.6, post-MVP).
2. A network LLM provider behind `HypothesisProvider` (opt-in, time/token-bounded). The gate and verifier already exist; only the transport is missing.
3. Multi-factor scenario sampling (currently single-factor only; uncovered combinations are reported).
4. Per-asset (rather than per-vulnerability) exploit conditions.
5. Time-split historical evaluation before any claim about real-world prediction (see `RESEARCH_EVALUATION.md`).
