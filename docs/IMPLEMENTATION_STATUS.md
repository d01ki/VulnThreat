# Implementation status

Scope of this pass: **M0–M3 (P0) only**. M4/M5 (P1/P2) were intentionally not started.
Legend: `[x]` done and covered by automated tests or a recorded manual check; `[ ]` not done.
Last updated: 2026-10-31.

## M0: scaffold, migration, settings, fixtures

- [x] Python package `tiw` (src layout), Python ≥ 3.12, dependency versions pinned in `uv.lock`
- [x] SQLAlchemy 2 models for every table in DESIGN §7 (`src/tiw/storage/models.py`)
- [x] Alembic migration `0001_initial`, applied by `tiw init`; schema-vs-model check (`test_schema_matches_models`)
- [x] Settings: workspace dir, display timezone (default Asia/Tokyo), brand name, fixed clock, synthetic/live mode
- [x] Synthetic fixtures for scenarios A–D (`src/tiw/demo_data/`, `DEMO-VULN-###` only)
- [x] Empty DB initialisation, offline start (`tiw init`, `tiw serve`); the empty state is rendered on every screen

## M1: imports, ledger, observations, assets

- [x] KEV / EPSS saved-response import (official layouts; live CVE format validated)
- [x] Assets CSV, findings CSV, observations JSONL (+ `sensor_window` records), reviewed claims JSON
- [x] Content-addressed raw storage; idempotency on input hash + adapter version; identical rows add no history
- [x] Row errors with line, field and reason; whole-file rollback by default, `--allow-partial` opt-in
- [x] Observation dedup, future-time quarantine (5 min skew), day precision, evidence minimisation/masking
- [x] Append-only claim reviews, retractions, `supersedes`, explicit citation relations, document revisions
- [x] Append-only enforcement at the ORM level (`test_append_only_tables_reject_updates`)

## M2: assessment, delta, policy-v1

- [x] Separate axes: public_exploitation, local_activity (per asset), recency, conflict, independence, epss
- [x] Citation graph with SCC collapse; unknown-origin roots reported as unresolved and not counted
- [x] KEV record missing ≠ retraction; latest snapshot by `dateReleased`; failed import keeps evidence
- [x] Intelligence deltas for meaningful changes only, with affected findings and re-evaluated decision IDs
- [x] policy-v1 rules 1–9, context reason codes, unknowns, in-urgency ordering (`tests/unit/test_policy.py`)
- [x] Investigation tasks from templates, grouped, ordered (urgent/high count → total → effort)

## M3: UI, diff, investigation queue, exports

- [x] CLI: `tiw init/import/assess/serve/export/set/demo seed|advance|status|reset`
- [x] REST API `/api/v1` (all endpoints in DESIGN §14 + task resolve), bearer token, error envelope, OpenAPI
- [x] Server-rendered UI per UI_DESIGN.md: Threat Changes (home), Threats, Threat Detail, Observations, Affected Assets, Decision Diff, Investigation Queue, Sources & Health, Import (validate → confirm), Settings
- [x] JSON / Markdown export (CLI, API, UI download), untrusted text escaped
- [x] Demos A–D run offline from the CLI and appear in the UI (`tests/integration/test_scenarios.py`)
- [x] Tests: 105 passing (`uv run pytest`): rule boundaries, idempotency, determinism, correction isolation, unknown/missing data, scan ≠ exploit, unmapped observations, KEV missing, conflict, escaping, CSP, CSRF, Host/Origin, token, path traversal, size limits, GET does not modify
- [x] Screenshots at 390 / 768 / 1440 px (Chromium via Playwright). No horizontal page overflow on 9 screens × 3 widths; mobile drawer opens and closes with Esc; review dialog closes with Esc. Kept in `docs/images/`
- [x] README + `docs/en/overview.md`, `installation.md`, `usage.md`
- [ ] Docker image **not verified**: the Dockerfile is written, but the Docker daemon was not running on the development machine, so it was never built

## Design inconsistencies and adopted resolutions

| # | Issue | Resolution (safe-side meaning preserved) |
|---|---|---|
| 1 | IMPLEMENTATION_PROMPT refers to `docs/DESIGN.md` and `docs/UI_DESIGN.md`, but the files were at the repository root | Moved them unchanged into `docs/` |
| 2 | §18 shows `migrations/` at the repository root | Placed in `src/tiw/migrations/` so an installed package can run `tiw init`. Same Alembic content |
| 3 | §7 has no stable key for claims, so relations and retractions across files could not reference them | Added `claims.claim_key` (unique per revision). Relations and retractions use it; the newest revision with that key wins |
| 4 | Several append-only tables have no total order when the fixed clock gives equal timestamps | Added an integer `seq` to source_revisions, asset_revisions, applicability_reviews, claim_reviews, intelligence_deltas, decisions |
| 5 | §7 lists no table for the set of known vulnerabilities | Added `vulnerabilities` (id, synthetic, title, first_seen_at) as a registry. It is not evidence |
| 6 | §9.4's delta list cannot express "first unconfirmed report" or "KEV record disappeared", although §9.3 requires the latter to be a change candidate | Added `exploitation_reported` and `kev_record_missing`. Neither raises urgency |
| 7 | §10 rule 6 reason code `KEV_AND_EXPOSED` is inaccurate when confirmation comes from a reviewed primary report | `KEV_AND_EXPOSED` is used when KEV is among the bases, otherwise `CONFIRMED_AND_EXPOSED`. `CONFIRMED_AND_CRITICAL` covers the critical branch |
| 8 | §10 rule 2 says "not_affected and local exploit attempt, etc." | Implemented for a confirmed local `exploit_attempt` (a compromise already matches rule 1). Other contradiction types are not inferred |
| 9 | §10 rule 3 needs "valid" not_affected; an expiry is required by §8 | A `not_affected` without expiry, or past it, is treated as expired (rule 4) |
| 10 | Reports whose only cited source was retracted would otherwise keep a "reported" status alive | Active reports whose every explicit citation path ends at retracted or rejected claims are excluded and shown as "cited source retracted" |
| 11 | Context-only changes (e.g. `EPSS_STALE`) alter `reason_codes` | A new decision is recorded (history stays accurate), and the diff states that action and urgency did not change. Evidence-ID-only changes do not create decisions |
| 12 | `tiw assess --changed` cannot know which inputs are clock-dependent | P0 re-evaluates every vulnerability; writes only happen when canonical output changes (idempotent). Not yet measured at the §17 scale targets |
| 13 | KEV/sensor freshness thresholds are unspecified (only EPSS 72 h) | KEV source stale after 7 days, recorded as a product default. No threshold is set for advisory sources |
| 14 | Demo steps from different scenarios share one fixed clock | `tiw demo advance` applies pending steps of all scenarios in global clock order; the clock never moves backwards |
| 15 | UI "Mark resolved" for every task would conflict with automatic regeneration | Only correction-review tasks can be closed manually; other tasks close automatically when their evidence arrives |
| 16 | Live workspace vs synthetic CSV rows | Live workspaces reject records flagged synthetic. In a synthetic workspace every record is treated as synthetic |
| 17 | Docker needs a non-loopback bind inside the container | The CLI refuses non-loopback hosts. The image binds 0.0.0.0 inside the container, and the docs say to publish on 127.0.0.1 only |

## Not implemented / constraints

- **Not implemented (P1/P2 by design):** `tiw fetch` (live KEV/EPSS), Suricata/log adapters, OSV, LLM claim extraction, MISP/OpenCTI/STIX/VEX, multi-user/RBAC, notifications, PostgreSQL, FTS5 search.
- **Not measured:** performance at 1,000 assets / 10,000 findings / 50,000 observations (each import currently recomputes every vulnerability), accuracy against real data, the comparison against CVSS-only and KEV+EPSS baselines, and review-time effects. No claims are made about them.
- The synthetic demo checks behaviour only. It is not evidence of real-world accuracy.
- The Dockerfile has not been built or run (see M3).
- Screenshots were taken with Playwright Chromium only. No other browsers or assistive technology were tested. Colour contrast follows the token values; a full contrast audit tool was not run.
- Single trusted local analyst: there is no authentication in the UI beyond localhost binding, Host/Origin checks and CSRF. The API uses a local bearer token.
- License (Apache-2.0) is a candidate, not confirmed.
