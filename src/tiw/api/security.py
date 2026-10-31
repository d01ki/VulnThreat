"""Local-only security boundaries: Host/Origin checks, CSRF, API token, response headers (DESIGN §15)."""

from __future__ import annotations

import secrets
from typing import Iterable
from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response

CSRF_COOKIE = "tiw_csrf"
CSRF_FIELD = "csrf_token"
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)


def error_body(code: str, message: str, details: list | None = None) -> dict:
    return {"error": {"code": code, "message": message, "details": details or []}}


class LocalGuardMiddleware(BaseHTTPMiddleware):
    """Reject unexpected Host headers (DNS rebinding) and cross-origin state changes."""

    def __init__(self, app, allowed_hosts: Iterable[str]):  # type: ignore[no-untyped-def]
        super().__init__(app)
        self.allowed = {h.lower() for h in allowed_hosts}

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        host = (request.headers.get("host") or "").lower()
        if host not in self.allowed:
            return _deny(request, "bad_host", "Host header not allowed")
        if request.method not in SAFE_METHODS:
            origin = request.headers.get("origin")
            if origin and origin != "null":
                o = urlsplit(origin)
                if (o.netloc or "").lower() != host:
                    return _deny(request, "bad_origin", "Cross-origin request rejected")
            elif origin == "null":
                return _deny(request, "bad_origin", "Opaque origin rejected")
        response: Response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response


def _deny(request: Request, code: str, message: str) -> Response:
    if request.url.path.startswith("/api/"):
        return JSONResponse(error_body(code, message), status_code=403)
    return PlainTextResponse(message, status_code=403)


def csrf_token_for(request: Request) -> str:
    tok = request.cookies.get(CSRF_COOKIE)
    if not tok or len(tok) < 20:
        tok = getattr(request.state, "new_csrf", None) or secrets.token_urlsafe(32)
        request.state.new_csrf = tok
    return tok


def set_csrf_cookie(request: Request, response: Response) -> None:
    tok = getattr(request.state, "new_csrf", None)
    if tok:
        response.set_cookie(CSRF_COOKIE, tok, httponly=True, samesite="strict", path="/")


def check_csrf(request: Request, submitted: str | None) -> bool:
    cookie = request.cookies.get(CSRF_COOKIE)
    return bool(cookie and submitted and secrets.compare_digest(cookie, submitted))


def check_token(request: Request, expected: str) -> bool:
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        return False
    return secrets.compare_digest(auth[7:].strip(), expected)
