# Arsenal demo: evidence-grounded attack paths and counterfactual patch triage

Everything is offline and synthetic: no API keys, no LLM, no WAF/IDS/SIEM logs, no scanning, no exploit execution. The clock is fixed, so every run shows the same numbers and the same path ids. All assets, vulnerabilities (`DEMO-VULN-1xx`), CVSS values, KEV/EPSS records and claims are fictional and labelled synthetic.

## Online snapshot (no install)

https://d01ki.github.io/VulnThreat/ is a static, read-only snapshot of this demo, rebuilt from `main` by `.github/workflows/pages.yml` (`scripts/build_static_demo.py`). Every page, budgets 0–5 × both objectives × every baseline, and single-factor what-ifs are pre-rendered; "Reset" and "Step 2" switch between the step-1 and step-2 snapshots. Imports, Network Paths editing, recording runs, multi-factor what-ifs and other values show a "run locally" note.

## Setup (once, ~1 minute)

```powershell
uv sync
uv run tiw demo reset --yes            # removes an old synthetic demo workspace (refuses live ones)
uv run tiw demo seed --scenario attack-path
uv run tiw serve --data-dir .tiw-demo  # http://127.0.0.1:8787
```

Docker: `docker run --rm -p 127.0.0.1:8788:8787 -e TIW_MODE=demo threat-workbench` (attack-path is the default demo; `-e TIW_DEMO_SCENARIO=legacy` serves scenarios A–D). Scenarios A–D and attack-path use separate workspaces because each ships its own synthetic KEV snapshot.

## The fixture

| | |
|---|---|
| Assets (7) | public web, VPN gateway, partner SFTP (exposed); payments API, admin console; finance DB and HR DB (crown jewels, weights 3 and 2) |
| Findings (7) | `DEMO-VULN-101` web (CVSS 9.8), `105` VPN (9.1), `104` admin (8.8), `107` SFTP (8.1, in the synthetic KEV), `102` API (7.2), `103` finance DB, `106` HR DB |
| Evidence | reviewed firewall export; **disputed** VPN→API reachability (network-team claim says blocked); **unknown** web→admin edge (admin VLAN not in the export); SFTP→API supported only by a reviewed runbook claim |
| Actions (10) | patches (effort 1–2), credential vaulting, proxy + edge restriction (dependency), HR isolation (conflicts with HR patch, high downtime) |

## Script

**1. Attack Paths: no sensor data needed.** Open http://127.0.0.1:8787/attack-paths (or `uv run tiw graph build --data-dir .tiw-demo`).
Point out: 7 model paths to 2 crown jewels; **4 supported, 2 contradicted (VPN dispute), 1 conditional (unknown admin edge)**; nothing came from WAF/IDS logs. The banner says synthetic. Stress that paths are hypotheses, not observed attacks.

**2. Evidence Inspector.** Click `PATH-0393D77E03` (internet → SFTP → API → finance DB). Each hop lists its facts and every evidence item: the SFTP→API topology record is *inactive (unreviewed)*, so the edge stands only on claim `g-sftp-api`. Then open the VPN edge (`/attack-paths?edge=e-vpn-api`): support and refutation are both active, so it is **disputed**, and no vote resolves it. The hypothesis panel shows the deterministic generator's candidates and their verification states.

**3. Remediation Lab, budget 2.** Open `/remediation-lab` (`uv run tiw triage optimize --budget 2 --data-dir .tiw-demo`).
- Graph-aware exact optimum: **`A-patch-api`** (effort 2): weighted paths **17 → 2**.
- Highest CVSS first, same budget: `A-patch-web + A-patch-vpn`: 17 → **5**. KEV-first 5, EPSS-first 10, criticality/exposure 9.
- Why: the payments API is a **shared choke point**; patching it breaks 6 of 7 counted paths, while the two highest-CVSS fixes leave the SFTP route to both databases open.

**4. Residual exposure and assumptions.** The one surviving path is `PATH-968F2E143B` (web → admin → HR), which runs through the *unknown* admin edge. Unknown is not treated as safe. Open "Model assumptions and limits": it states the objective semantics, that EPSS is never multiplied along a path, which action effects are unverified, and that enumeration was not truncated.

**5. Robustness: retract one report.** Open `/robustness` (`uv run tiw triage robustness --budget 2 --data-dir .tiw-demo`).
`A-patch-api` is selected in **20 of 22** enumerated scenarios (a count of constructed cases, **not a probability**). Two flips:
- *Withdraw claim `g-sftp-api`* → `A-patch-vpn + A-patch-web`: the SFTP→API edge becomes `unsupported`, so the two SFTP paths become *insufficient evidence* and are excluded.
- *Evaluate 90 days later*: firewall-export rows expire, the VPN refutation is left alone, and the VPN paths are blocked.

Use the what-if selector (withdraw `claim:g-sftp-api`) to show the paired before/after and the evidence behind each changed fact.

Then make it real: click **"Step 2: retract the SFTP runbook claim"** (or `uv run tiw demo advance --step 2 --scenario attack-path --data-dir .tiw-demo`). The publisher's correction is imported as a retraction. The Remediation Lab now recommends `A-patch-vpn + A-patch-web` (weighted 12 → 0). The recorded run's **decision diff** says:
`PATH-0393D77E03 supported→insufficient_evidence (no longer counted): edge:e-sftp-api satisfied→unsupported`, and `claim:g-sftp-api inactive: retracted`. The two SFTP paths stay visible under "Excluded from the objective": they are unverified, not safe. The `graph_only` baseline (provenance ignored) still recommends `A-patch-api`.

**6. Reproducibility.** Click **Reset demo (step 1)**, or:

```powershell
uv run tiw demo reset --yes; uv run tiw demo seed --scenario attack-path
uv run tiw export --analysis-run latest-optimize --format json --normalized --stdout --data-dir .tiw-demo
```

The normalized JSON is byte-identical across resets (`tests/integration/test_attack_path.py::test_step6_repeat_demo_gives_identical_normalized_json`). Exports carry the evidence snapshot hash, algorithm version and tie-breaking rule.

## Screen-capture tips

- Use 1440×900. Graph, Lab and Robustness each fit in one or two screens; at 390 px the graph and wide tables scroll inside their cards.
- Keep the synthetic banner visible. Do not describe numbers as risk, probability or breach likelihood.
