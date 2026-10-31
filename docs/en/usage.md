# Usage

## CLI

```text
tiw init [--data-dir DIR] [--synthetic]
tiw import {kev|epss|assets|findings|observations|claims} FILE [--allow-partial] [--dry-run] [--json]
tiw assess [--changed | --all] [--id DEMO-VULN-001 ...]
tiw serve [--host 127.0.0.1] [--port 8787]
tiw export --threat ID [--format markdown|json] [--stdout]
tiw set {timezone|brand_name} VALUE
tiw demo seed [--scenario escalation|amplification|expiry|correction|all]
tiw demo advance --step N [--scenario NAME]
tiw demo status
tiw demo reset --yes
```

- Every import is validated first. By default one invalid row rejects the whole file and nothing is written. `--allow-partial` keeps valid rows and reports the rejected ones (line, field, reason). Rejected values are never echoed back.
- Re-importing an identical file (same SHA-256 and adapter version) is a no-op. Identical rows in a different file add no history.
- Every import ends with a recompute. Run `tiw assess` after time passes, so that expiry of exposure evidence, `not_affected` reviews and EPSS is applied. In P0 `--changed` re-evaluates every vulnerability; this is idempotent.
- `tiw fetch` (live KEV/EPSS) is **not implemented**. It is planned for milestone M4.

## Import formats

Limits: 10 MB and 50,000 records per file. Archives and executables are rejected. All timestamps need an explicit offset (`Z` or `+09:00`).

### Assets CSV

```csv
asset_id,name,criticality,internet_exposed,observed_at,expires_at
asset-1,public-gateway,critical,true,2026-10-01T00:00:00Z,2026-10-08T00:00:00Z
```

`criticality`: `critical|high|normal`. `internet_exposed`: `true|false|unknown`. Optional columns: `owner`, `synthetic`. Any other columns are kept as context. An empty `expires_at` means the record never expires.

### Findings CSV

```csv
finding_id,asset_id,vulnerability_id,applicability,observed_at,rationale,evidence_ref,reviewer,expires_at
f-1,asset-1,CVE-2026-0001,affected,2026-10-01T00:00:00Z,,,,
f-2,asset-2,CVE-2026-0001,not_affected,2026-10-01T00:00:00Z,module disabled,config:123,alice,2026-11-01T00:00:00Z
```

A `not_affected` row without `rationale`, `evidence_ref`, `reviewer` and `expires_at` is rejected. It is never silently adopted. Assets must be imported first.

### Observations JSONL

```json
{"schema_version":"1.0","sensor_id":"ids-1","external_event_id":"e-001","observed_at":"2026-10-02T10:00:00Z","asset_id":"asset-1","vulnerability_id":"CVE-2026-0001","event_type":"exploit_attempt","mapping_status":"reviewer_confirmed","evidence":{"rule_id":"r-1"}}
{"schema_version":"1.0","record_type":"sensor_window","sensor_id":"ids-1","start":"2026-10-01T00:00:00Z","end":"2026-10-08T00:00:00Z","status":"ok","coverage":{"assets":["asset-1"]}}
```

- `event_type`: `scan | exploit_attempt | compromise_confirmed`. `compromise_confirmed` requires `reviewer` and `rationale`.
- `mapping_status`: `reviewer_confirmed | explicit | unconfirmed`. Unconfirmed mappings are stored and shown, but never raise a vulnerability's priority.
- Deduplication uses `(sensor_id, external_event_id)`, or a hash of the normalised record when there is no event ID.
- Timestamps more than 5 minutes in the future are quarantined. Date-only values keep day precision.
- Evidence is minimised: keys that look like secrets are masked, raw bodies are dropped, and values are size-capped.

### Claims JSON (reviewed advisories)

```json
{"schema_version":"1.0","source":{"name":"Vendor PSIRT","kind":"advisory"},
 "documents":[{"external_id":"psirt/2026-01","title":"…","published_at":"2026-10-04T09:00:00Z","text":"…",
   "claims":[{"claim_key":"psirt-1","subject_id":"CVE-2026-0001","predicate":"exploited_in_wild","value":true,
              "quote":"…","locator":"paragraph 2","origin":"vendor","review_state":"reviewed",
              "reviewer":"alice","review_reason":"first-hand IR statement",
              "relations":[{"kind":"cites","to":"other-claim-key","verification":"explicit"}]}],
   "retractions":[{"claim_key":"old-claim","reason":"publisher withdrew the report","reviewer":"alice"}]}]}
```

- `origin`: `primary | secondary | vendor | model`. `model` claims can only be `candidate` and never count.
- A new revision of the same `external_id` replaces that document's earlier claims. The earlier revision is kept.
- Document text and quotes are data. They are escaped when displayed and never interpreted as instructions.

### KEV / EPSS

Saved responses in the official layouts (the KEV catalog JSON, and the EPSS API `{"status":"OK","data":[…]}`). The live CVE format is validated. Synthetic files must set `"synthetic": true` and use `DEMO-VULN-###`.

## Web UI

`tiw serve` binds to `127.0.0.1:8787`.

| Screen | Purpose |
|---|---|
| Threat Changes | KPIs (new intel changes, local attempts, assets to reassess, open questions), activity chart (public = blue solid line, local = green dashed line, sensor outages hatched rather than drawn as zero), evidence status, latest changes, source health, priority investigations, decision changes. The period selector applies to all of them and is kept in the URL |
| Threats / Threat Detail | Evidence status, assessment axes, timeline, and Evidence / Observations / Assets / Decisions tabs. Claims can be reviewed in a dialog (append-only, reason required). JSON/Markdown export |
| Observations | Mapped, unmapped and quarantined events, plus sensor coverage |
| Affected Assets | Current decision per finding with reason codes and unconfirmed conditions |
| Decision Diff | Before/After of every condition (changed rows tinted), "Why this changed", triggering deltas, evidence added or no longer used, and the full decision history |
| Investigation Queue | Grouped questions with the evidence needed. Correction-review tasks are closed manually; others close automatically |
| Sources & Health | Last successful update, last failure, freshness, import runs and their errors, coverage, quarantine |
| Import | Choose file → validation result → confirm import |
| Settings | Display timezone; read-only workspace facts |

Every form is protected by a CSRF token. Requests with an unexpected `Host` or a cross-origin `Origin` are rejected. Pages are served with a strict Content-Security-Policy (no inline script or style), and all untrusted text is HTML-escaped.

## REST API

Base path `/api/v1`. OpenAPI is at `/api/v1/openapi.json`, docs at `/api/docs`. Every request needs `Authorization: Bearer <token>`, where the token is the `api_token` file in the workspace. Tokens are never accepted in the URL. CORS is disabled.

| Method and path | Purpose |
|---|---|
| `POST /imports/{kind}` | Multipart `file`; query `allow_partial`, `dry_run` |
| `GET /imports/{id}` | Import run result |
| `GET /threats` | `status`, `period`, `q`, `cursor`, `limit` |
| `GET /threats/{id}` | Current assessment, evidence, observations, assets |
| `GET /threats/{id}/timeline` | Assessment versions and deltas |
| `GET /evidence/{id}` | Claim or observation metadata (text is returned raw; escape it when rendering) |
| `POST /claims/{id}/reviews` | `{"reviewer","state","reason","relation"?}`; reason required |
| `GET /findings/{id}/decisions` | Decision history |
| `GET /decisions/{id}/diff` | Comparison with the previous decision |
| `POST /assessments/recompute` | `{"vulnerability_ids": [...]}` or all |
| `GET /investigations` | Queue; `include_resolved` |
| `POST /investigations/{id}/resolve` | Correction-review tasks only |
| `POST /exports` | `{"vulnerability_id","format":"json|markdown"}`, written to `exports/` |
| `GET /health/sources` | Freshness and failures |

Errors use `{"error":{"code":"…","message":"…","details":[]}}`. Status codes: 401 for a missing token, 404 when nothing is found, 409 for a conflict, 413 when a file is too large, and 422 for invalid input.

```powershell
$t = Get-Content .tiw-demo\api_token
curl.exe -H "Authorization: Bearer $t" http://127.0.0.1:8787/api/v1/threats
```
