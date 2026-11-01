# v2 data formats

All files are UTF-8 JSON objects with `"schema_version": "1.0"`, max 10 MB. **Unknown keys are rejected** at every level, so no payload, command or script can ride along. Identifiers: letters, digits, `- _ . :` (max 58 for graph ids). Timestamps need an explicit offset (`Z`). Invalid content rejects the whole file unless `--allow-partial` is passed. Re-importing identical content is a no-op. In a live workspace, `"synthetic": true` is rejected.

Import order: assets → findings → (claims) → topology → exploit conditions → remediations.

**Shortcut:** only `assets.csv`, `findings.csv` and the network paths must be provided by hand, and the paths need no JSON (see *Network paths CSV / screen*). Exploit conditions and remediations can be generated as drafts from the imported findings (see *Drafts* below). Templates for all three JSON files: Import screen → "Download template", or `GET /import/template/{topology|exploit_conditions|remediations}`.

```text
tiw import topology topology.json
tiw import exploit-conditions exploit_conditions.json
tiw import remediations remediations.json
```
REST: `POST /api/v1/imports/{topology|exploit_conditions|remediations}` (multipart `file`).

## Network paths CSV / screen (no JSON needed)

```csv
source,target,ports,reachability,evidence_ref,reviewer
internet,web-01,443,allowed,fw rule 10,alice
web-01,app-01,8443 8080,allowed,fw rule 20,alice
app-01,db-01,5432,unknown,segment not in the export,alice
```

`tiw import topology-csv edges.csv` (also `edges`), Import screen kind `topology_csv`, or the **Network Paths** screen (`/topology`: add/delete paths and set crown-jewel weights in the browser). `tiw graph edges --out edges.csv` and `/topology.csv` export the current topology in the same format, so you can edit and re-import it.

| Column | Required | Notes |
|---|---|---|
| `source` | yes | `internet` or `entry:<name>` = entry point; otherwise an imported asset id. **An unknown name is an error, never a new entry point** |
| `target` | yes | Imported asset id |
| `ports` | network | `443`, `tcp/443`, `udp/53`; several separated by spaces or `;` |
| `reachability` | no | `allowed` (default), `unknown` (never read as blocked), `blocked` |
| `evidence_ref` | yes* | Citation; *or `claim_keys` |
| `reviewer` | no | Filled = reviewed. Empty = unreviewed: an `allowed` edge with no reviewed claim is *unsupported*, and paths through it are excluded as insufficient evidence |
| optional | | `kind` (`network`/`trust`), `requires_capability`, `grants_capability` (trust edges), `valid_from`, `valid_until`, `claim_keys`, `label`, `source_zone`, `destination_zone`, `control`, `id` (default `e-<source>-<target>`) |

Crown jewels, in priority order: (1) assets with a `crown_jewel_weight` column in `assets.csv` (integer 1–1000); (2) the current topology's objectives; (3) every `critical` asset, each with weight **1** (relative importance is never guessed). The choice is written into the topology description. Node zones come from an optional `zone` column in `assets.csv`. A CSV import **replaces** the whole topology as a new version; the screen edits the current version. Both are converted to a `topology.json` document and validated by the same rules below; errors are reported against CSV line numbers.

## topology.json

| Field | Required | Notes |
|---|---|---|
| `source.name` | yes | Provenance (e.g. firewall export name); `source.evidence_ref` optional |
| `observed_at` | no | Snapshot time |
| `entry_points[]` | ≥1 | `id`, `label`, `grants` (capability, default `network_access`) |
| `nodes[]` | | `asset_id` (must be an imported asset), `zone`, `label` |
| `objectives[]` | ≥1 | `id`, `asset_id`, `label`, `weight` (integer 0–1000, configured), `required_capabilities` |
| `edges[]` | | see below; max 10,000; nodes max 2,000 |

Edge fields: `id`, `source`, `target`, `kind` (`network`/`trust`), `ports` (`tcp/443`, required for network), `reachability` (`allowed`/`blocked`/`unknown`), `review_state` (`reviewed` needs `reviewer`), `evidence_ref` and/or `claim_keys` (**at least one: unanchored edges are rejected**), `valid_from`, `valid_until`, `source_zone`, `destination_zone`, `control`, `label`; trust edges need `requires_capability` and `grants_capability`.

Rejected: duplicate ids, duplicate `(source, target, kind, ports)`, self-loops, edges into entry points, unknown nodes, unknown claim keys, claims whose subject is not `edge:<this id>` with predicate `reachability`, `valid_until <= valid_from`, non-finite numbers.

`reachability: unknown` stays unknown (never "blocked"). `allowed` with `review_state: unreviewed` and no active claim yields an **unsupported** fact.

## exploit_conditions.json

`vulnerabilities[]` entries:

| Field | Required | Notes |
|---|---|---|
| `vulnerability_id` | yes | Must have at least one imported finding (orphans rejected). Synthetic workspaces: `DEMO-VULN-###` only |
| `service_ports` | yes | Ports the vulnerable service listens on. `["any"]` = port not recorded: matches every open port of an edge **and adds an `unknown` fact `cond:<vuln>:service-port`**, so such paths are at best *conditional* |
| `requires_capability` / `grants_capability` | yes | Abstract attacker states (`network_access`, `user_context`, `code_execution`, `admin_context`, `credential_access`, `data_access`) |
| `citation` | yes | Source of the preconditions |
| `review_state`, `reviewer` | | |
| `cvss` | no | `version`, `base_score` 0–10, `source` required, `vector` optional. Used only by the `cvss_desc` baseline |
| `conditions[]` | no | `id`, `kind` (`affected_component`, `authentication`, `configuration`, `attacker_capability`, `network_service`), `status` (`satisfied`/`not_satisfied`/`unknown`), `evidence_ref` or `claim_keys` (required unless unknown), `description`, `review_state`, `reviewer`, `expires_at` |

Conditions are per vulnerability (all findings of it share them). Fact id: `cond:<vulnerability_id>:<condition id>`.

## remediations.json

`actions[]` entries: `id`, `type` (`patch_finding` + `finding_id`; `restrict_edge` + `edge_id`; `disable_service` + `asset_id` + `ports`; `isolate_asset` + `asset_id`; `enabler`), `label`, `cost` (non-negative **integer**; floats, booleans, negatives and NaN rejected), `downtime` (`none`/`low`/`high`), `requires[]` (other action ids; cycles rejected), `conflict_group`, `verification_status` (`verified`/`unverified`), `preconditions[]`, `notes`. Optional top-level `cost_unit` (display only).

References must exist (findings, assets, and edges of the latest topology). Actions whose scope later leaves the graph are skipped at analysis time.

## Graph-evidence claims (existing claims format)

```json
{"claim_key": "g-sftp-api", "subject_id": "edge:e-sftp-api", "predicate": "reachability", "value": true,
 "origin": "primary", "review_state": "reviewed", "reviewer": "analyst", "review_reason": "runbook"}
```

`predicate`: `reachability` (subject `edge:<edge id>`) or `precondition` (subject `cond:<vulnerability>:<condition id>`); `value` boolean (`true` supports, `false` refutes). Retractions, rejections, `supersedes` and reviews use the existing claims machinery. Only effectively `reviewed` claims count.

## Hypothesis candidates (untrusted)

`tiw graph hypotheses --from-file cand.json` or `POST /api/v1/graph/hypotheses {"candidates": [...]}`. Each item:

```json
{"schema_version": "1.0", "hypothesis_id": "H-001", "source_asset_id": "ap-web-01", "target_asset_id": "ap-api-01",
 "technique_id": "T0000", "candidate_vulnerability_id": "DEMO-VULN-102",
 "required_conditions": ["network_reachability", "affected_component"],
 "supporting_evidence_ids": ["topology:e-web-api"], "assumptions": [], "rationale": "candidate"}
```

Unknown keys, unknown nodes/findings, fabricated evidence ids and malformed fields are rejected with reasons. Accepted candidates are only verified against recorded facts; they never change the graph. `T0000` is a placeholder; other technique ids are shown but not validated (no pinned ATT&CK snapshot is shipped) and never used for attribution.

## Drafts (generated from your findings)

```text
tiw draft all --import                      # generate and import both drafts
tiw draft exploit-conditions --out ec.json  # or write an editable file
tiw draft remediations --out rem.json
```
UI: Import → "Generate and import drafts" (CSRF-protected POST) or the download links. REST: `GET /api/v1/drafts/{exploit_conditions|remediations}`, `POST /api/v1/drafts/import`.

What a draft contains, and what it deliberately does not invent:

| Draft | Generated | Never invented |
|---|---|---|
| exploit conditions | one entry per vulnerability that has a finding: `service_ports: ["any"]`, `network_access` → `code_execution`, `review_state: unreviewed`, no conditions | ports, CVSS, review state, citations (citation text says "draft: not yet researched") |
| remediations | one `patch_finding` per finding without one: effort `1` (placeholder), downtime `low`, `unverified` | real effort, edge restrictions, dependencies |

Existing curated entries are kept verbatim and in order; only missing ones are appended. Re-running on an already-complete catalogue is a no-op. Because `any` ports add an unknown fact, no path that crosses a drafted vulnerability can be `supported`. Refine the draft (ports, capabilities, effort) and re-import to tighten the analysis.

## Exports

`tiw export --analysis-run <id|latest-optimize|latest-robustness|latest-graph> --format json|markdown [--normalized]`, `GET /api/v1/analysis-runs/{id}?format=json|markdown|normalized`, and the UI download links. Contents: evidence snapshot hash, result hash, algorithm version, clock, input content hashes, objective semantics and tie-breaking, params, selected portfolio with per-action reasons, ties, alternatives, baselines, counted/excluded/surviving paths, scenario set and flip reasons, assumptions, and the diff to the previous run. `--normalized` emits only the deterministic result.
