"""Security headers + structured request logging middleware
(THREAT_MODEL.md §5.1, ARCHITECTURE.md §11)."""
from __future__ import annotations

import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.core.logging import get_logger, request_id_ctx

logger = get_logger("app.request")


def set_security_headers(response: Response) -> Response:
    """Apply the API-wide policy, including responses built outside middleware.

    Starlette's outer ServerErrorMiddleware constructs unhandled 500 responses
    after inner middleware unwinds, so exception handlers must call this too.
    """
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    # Auth endpoints return bearer/refresh tokens and /me returns account
    # details. Prevent browsers and shared intermediaries from retaining
    # any API response, including errors and future authenticated routes.
    # This API serves no intentionally cacheable static assets.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        return set_security_headers(await call_next(request))


def _safe_route_path(request: Request) -> str:
    """Log route templates, never attacker-controlled raw URL path segments.

    A matched FastAPI route exposes a stable path such as
    /api/v1/rules/{rule_id}. Unmatched paths (including 404s and errors
    raised before routing) may contain arbitrary secrets or log-control
    characters, so use a fixed sentinel rather than request.url.path.
    """
    route = request.scope.get("route")
    template = getattr(route, "path", None)
    if isinstance(template, str) and template.startswith("/") and len(template) <= 256:
        return template
    return "<unmatched>"


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = str(uuid.uuid4())
        token = request_id_ctx.set(request_id)
        start = time.perf_counter()
        try:
            try:
                response = await call_next(request)
            except Exception:
                # Starlette's outer error middleware builds the final response.
                # Log while the request context is still active, without
                # disclosing exception text, request headers, or query values.
                logger.error(
                    "request raised an exception",
                    extra={"extra_fields": {
                        "request_id": request_id,
                        "method": request.method,
                        "path": _safe_route_path(request),
                        "outcome": "exception",
                        "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                    }},
                )
                raise
            response.headers["X-Request-ID"] = request_id
            logger.info(
                "request handled",
                extra={"extra_fields": {
                    "request_id": request_id,
                    "method": request.method,
                    "path": _safe_route_path(request),
                    "status_code": response.status_code,
                    "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                }},
            )
            return response
        finally:
            request_id_ctx.reset(token)
