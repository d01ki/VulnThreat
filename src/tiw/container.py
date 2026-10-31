"""Container entrypoint: `python -m tiw.container`.

TIW_MODE=live (default): initialise (or reuse) the persistent workspace in /data/workspace.
TIW_MODE=demo: seed the synthetic scenarios into a separate /data/demo workspace.
The server binds all interfaces inside the container; publish the port on 127.0.0.1 only.
"""

from __future__ import annotations

import os

import uvicorn

from tiw.api.app import create_app
from tiw.storage import db


def main() -> None:
    mode = os.environ.get("TIW_MODE", "live").lower()
    port = int(os.environ.get("TIW_PORT", "8787"))
    if mode == "demo":
        from tiw.services import demo

        ws = db.resolve_workspace(os.environ.get("TIW_DEMO_DIR", "/data/demo"))
        demo.seed(ws, "all")
        demo.advance(ws, 4)
    elif mode == "live":
        ws = db.resolve_workspace(os.environ.get("TIW_DATA_DIR", "/data/workspace"))
        db.init_workspace(ws, synthetic=False)
    else:
        raise SystemExit("TIW_MODE must be live or demo")
    print(f"threat-intel-workbench ({mode}) on http://127.0.0.1:{port}  workspace={ws.data_dir}", flush=True)
    app = create_app(ws, port=port, extra_hosts=(f"localhost:{port}", f"127.0.0.1:{port}"))
    uvicorn.run(app, host="0.0.0.0", port=port)  # noqa: S104 - container boundary; publish on 127.0.0.1


if __name__ == "__main__":
    main()
