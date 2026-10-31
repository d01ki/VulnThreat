# Overview

`tiw` turns public exploitation information and local observations into versioned evidence. It assesses each vulnerability on separate axes, records meaningful changes as *intelligence deltas*, and re-evaluates asset-level decisions with a deterministic, versioned policy. Every decision can be traced back to its inputs and compared with the decision it replaced.

Patch triage is where the intelligence gets used; it is not the product's centre. The home screen is **Threat Changes**, not a ranked CVE list.

## Questions the tool answers

1. What changed in the threat picture since last time?
2. Is it a local observation, a third-party report, or an inference?
3. Are multiple reports independent, or reposts of one source?
4. Which of our assets does it affect, and how does it change the decision?
5. What must be checked to settle an undecided case?

## Evidence model

| Concept | Stored as | Notes |
|---|---|---|
| Source revision | `source_revisions` | Content hash, publication/fetch time, synthetic flag, `supersedes_id`. Never modified. |
| Claim | `claims` | Subject, predicate (`exploited_in_wild`, `epss_score`, …), value, quote, locator, origin, initial review state |
| Review | `claim_reviews` | Append-only. The latest review gives the effective state (`reviewed`, `rejected`, `retracted`, …) |
| Relation | `claim_relations` | `cites` / `duplicates` / `supports` / `contradicts` / `supersedes`, with `explicit` / `reviewer_confirmed` / `candidate` verification |
| Observation | `observations` | `scan`, `exploit_attempt` or `compromise_confirmed`, a mapping status, and minimised evidence. Deduplicated per sensor |
| Sensor window | `sensor_windows` | Collection coverage and outages. "None observed" only means "not in imported, covered data" |
| Asset revision | `asset_revisions` | Exposure (`true`/`false`/`unknown`), criticality, observation time and expiry |
| Applicability review | `applicability_reviews` | `affected` / `not_affected` / `unknown`. `not_affected` requires a rationale, evidence reference, reviewer and expiry |

## Assessment axes (engine `assess-1`)

The axes are never merged into one score.

- **public_exploitation**: `confirmed` when KEV-listed or backed by a reviewed `primary`/`vendor` claim; `reported` when only unconfirmed reports exist; otherwise `unknown`. KEV listing does not mean exploitation is ongoing or that your assets are compromised.
- **local_activity**: the highest of `none_observed` < `scan` < `exploit_attempt` < `compromise_confirmed`, per asset, counting only observations with a confirmed vulnerability mapping.
- **recency**: `fresh` if the latest positive public evidence is within 30 days.
- **conflict**: positive and negative claims coexist. Never resolved by majority vote.
- **independence**: active report count, roots with a known first-hand origin, and roots of unknown origin. Only explicit or reviewer-confirmed `cites`/`duplicates` edges are used, and citation cycles are collapsed (strongly connected components).
- **epss**: probability, percentile, score date, and stale after 72 h. Optional.

KEV specifics: a record missing from the newest snapshot (by `dateReleased`) is **not** a retraction. The listing is kept and a `kev_record_missing` delta and investigation task are raised. A failed import changes nothing.

## Intelligence deltas

Generated only for meaningful changes: `exploitation_confirmed`, `exploitation_reported`, `local_attempt_observed`, `local_compromise_confirmed`, `claim_retracted`, `evidence_conflict`, `asset_exposure_changed`, `evidence_expired`, `applicability_changed`, `kev_record_missing`. Refetching identical data or adding reposts does not produce a threat-raising delta. Each delta records before/after, evidence IDs, affected findings, and the decision IDs that were re-evaluated.

## policy-v1

The first matching rule wins. This is a product policy, not SSVC.

| # | Condition | Action / urgency |
|---|---|---|
| 1 | Reviewed `compromise_confirmed` on the asset | incident_response / urgent |
| 2 | Valid `not_affected`, but a confirmed exploit attempt on the asset | investigate / urgent |
| 3 | Valid reviewed `not_affected`, no contradiction | monitor / low |
| 4 | Applicability unknown or `not_affected` expired | investigate / high if public confirmed or local attempt, else normal |
| 5 | Affected and confirmed local exploit attempt on the asset | remediate / urgent |
| 6 | Affected, public confirmed, and asset exposed or critical | remediate / urgent |
| 7 | Affected and public confirmed | remediate / high |
| 8 | Affected, exposure unknown or expired | investigate / high if critical, else normal |
| 9 | Affected otherwise | remediate / normal |

EPSS, reports of unconfirmed exploitation, scans, conflicts and staleness only add *context* reason codes. They never change the action or urgency. Within one urgency, results are ordered by criticality, then fresh EPSS (missing last), then finding ID.

Every decision stores: policy version, matched rule, reason codes, unconfirmed conditions, evidence IDs, the assessment, asset revision and applicability review it used, its inputs, and the previous decision.

## Investigation queue

Template-generated, no LLM. Findings that one check can settle are grouped: applicability per vulnerability, exposure per asset, contradiction per asset/vulnerability, KEV absence, EPSS refresh, and source corrections. The queue is ordered by the number of urgent/high cases affected, then total cases, then a configured effort value. This ordering is a heuristic, not an information-gain estimate.

## What it is not

No automatic patching, blocking, ticketing, exploit execution, internet scanning, attribution, or AI-attack detection. There is no single risk score, and no claims about detection rates or time savings: none have been measured.
