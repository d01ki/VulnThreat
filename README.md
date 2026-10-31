<div align="center">

# Threat Workbench

**Know which of your assets need action, and why.**

Public exploitation reports + attacks seen on your own sensors → a clear, explainable decision for every asset.

![Threat Changes](docs/images/home-1440.png)

</div>

## What it does

1. **You load** your assets and the CVEs your scanner found on them (CSV).
2. **It collects** evidence: the CISA KEV catalog, EPSS scores, reviewed advisories, and attacks your IDS/WAF saw.
3. **It decides** an action per asset (respond, patch, investigate, or monitor), with an urgency and the reason.
4. **It explains** every change: before and after, the evidence that moved it, and what is still unconfirmed.

## Why it's different

- **Evidence, not scores.** Exploited publicly? Attacked here? Exposed? Each is shown on its own.
- **Reposts don't count twice.** Ten articles citing one rumour are still one rumour.
- **Unknown stays unknown.** Missing data never becomes "safe". A scan is never treated as a breach.
- **History is never rewritten.** Corrections are added; old decisions stay comparable.
- **Local by design.** No API keys and no LLM. The only outbound requests are KEV/EPSS downloads that you start.

## Run it

```powershell
docker build -t threat-workbench .
docker run -d --name threat-workbench -p 127.0.0.1:8787:8787 -v tiw-data:/data threat-workbench
```

Open http://127.0.0.1:8787 and follow **Get started**: import assets → import findings → **Fetch KEV**.
Your data persists in the `tiw-data` volume.

<details>
<summary>Try the demo instead (synthetic data)</summary>

```powershell
docker run --rm -p 127.0.0.1:8788:8787 -e TIW_MODE=demo threat-workbench
```
Open http://127.0.0.1:8788.
</details>

<details>
<summary>Without Docker</summary>

```powershell
uv sync
uv run tiw init
uv run tiw import assets assets.csv
uv run tiw import findings findings.csv
uv run tiw fetch kev
uv run tiw serve            # http://127.0.0.1:8787
```
</details>

## Docs

[Overview](docs/en/overview.md) · [Installation](docs/en/installation.md) · [Usage](docs/en/usage.md) · [Status](docs/IMPLEMENTATION_STATUS.md)

<sub>CLI: `tiw` · License: Apache-2.0 (candidate)</sub>
