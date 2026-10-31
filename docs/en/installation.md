# Installation

## Requirements

- Python 3.12 or newer
- [uv](https://docs.astral.sh/uv/) (dependency versions are pinned in `uv.lock`)
- Windows PowerShell or a Linux shell

`uv sync` needs network access once, to download the pinned packages. At runtime the only outbound requests are the KEV/EPSS downloads you start (`tiw fetch`, or the buttons on Sources & Health).

## Install from source

```powershell
git clone <this repository>
cd <repository>
uv sync                    # creates .venv with pinned dependencies
uv run tiw --help
uv run pytest              # optional: run the test suite
```

## Workspaces

All data lives in a *workspace* directory:

| Path | Content |
|---|---|
| `tiw.db` | SQLite database (migrated with Alembic) |
| `objects/` | Raw imported files, content-addressed by SHA-256 (upload names are never used) |
| `staging/` | Files validated in the UI and awaiting confirmation |
| `exports/` | JSON/Markdown exports |
| `api_token` | Random bearer token for the local REST API |

The workspace is chosen with `--data-dir`, then `$TIW_DATA_DIR`, then `./.tiw`. The demo uses `./.tiw-demo` by default, so demo data is kept apart from real data:

- `tiw demo seed` refuses to write into a live workspace.
- A live workspace rejects records marked `"synthetic": true`.
- `tiw demo reset --yes` deletes only a synthetic workspace.

```powershell
uv run tiw init                      # live workspace in ./.tiw
uv run tiw init --data-dir D:\tiw    # elsewhere
```

`tiw init` is safe to re-run. It applies pending migrations and checks the schema without deleting anything.

## Docker

```powershell
docker build -t threat-workbench .
# real data (default): persistent workspace in the tiw-data volume
docker run -d --name threat-workbench -p 127.0.0.1:8787:8787 -v tiw-data:/data threat-workbench
# synthetic demo, kept separate
docker run --rm -p 127.0.0.1:8788:8787 -e TIW_MODE=demo threat-workbench
```

| Variable | Default | Meaning |
|---|---|---|
| `TIW_MODE` | `live` | `live` initialises or reuses `/data/workspace`; `demo` seeds scenarios A–D into `/data/demo` |
| `TIW_PORT` | `8787` | Port inside the container |

CLI commands run inside the container, for example `docker exec threat-workbench tiw fetch kev --data-dir /data/workspace`.

Inside the container the server binds to `0.0.0.0`, because the container itself is the isolation boundary. Publish the port on `127.0.0.1` only, as shown above. LAN exposure is not supported.

## Settings

| Setting | How |
|---|---|
| Display timezone (default `Asia/Tokyo`) | Settings page, or `tiw set timezone UTC` |
| Brand name (default "Threat Workbench") | `tiw set brand_name "…"` or `TIW_BRAND_NAME` before `tiw init` |
| Fixed clock (tests/demos) | Set by the demo per step; or `TIW_FIXED_NOW=2026-10-01T09:00:00Z` |
