"""FastAPI application factory."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from tiw import __version__
from tiw.api import rest, web
from tiw.api.security import LocalGuardMiddleware, error_body
from tiw.storage import db

STATIC = Path(__file__).resolve().parent.parent / "static"


def create_app(ws: db.Workspace, *, port: int = 8787, extra_hosts: tuple[str, ...] = ()) -> FastAPI:
    db.ensure_schema_present(ws)
    app = FastAPI(
        title="threat-intel-workbench API",
        version=__version__,
        description="Local REST API. Send `Authorization: Bearer <token>` (token file: <data_dir>/api_token).",
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/v1/openapi.json",
    )
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}", "127.0.0.1", "localhost", *extra_hosts}
    app.add_middleware(LocalGuardMiddleware, allowed_hosts=hosts)
    # CORS is intentionally not enabled.

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):  # type: ignore[no-untyped-def]
        if request.url.path.startswith("/api/"):
            if isinstance(exc.detail, dict) and "code" in exc.detail:
                return JSONResponse({"error": exc.detail}, status_code=exc.status_code)
            return JSONResponse(error_body(f"http_{exc.status_code}", str(exc.detail)), status_code=exc.status_code)
        return PlainTextResponse(str(exc.detail), status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):  # type: ignore[no-untyped-def]
        details = [{"loc": list(e.get("loc", [])), "msg": e.get("msg")} for e in exc.errors()]
        return JSONResponse(error_body("invalid_input", "Request validation failed", details), status_code=422)

    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")
    app.include_router(rest.build_router(ws))
    app.include_router(web.build_router(ws))
    return app
