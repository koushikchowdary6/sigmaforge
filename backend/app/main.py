"""FastAPI application factory.

Global exception handler maps every unhandled exception to a generic
RFC 7807 problem+json 500 response -- full details go to structured logs
only, never the HTTP response (THREAT_MODEL.md §5.4).
"""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.health import router as health_router
from app.auth.router import router as auth_router
from app.core.config import get_settings
from app.core.database import db_manager
from app.core.logging import configure_logging, get_logger
from app.core.middleware import RequestLoggingMiddleware, SecurityHeadersMiddleware

logger = get_logger("app.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging("DEBUG" if settings.debug else "INFO")
    db_manager.init(settings.database_url)
    logger.info("startup complete", extra={"extra_fields": {"environment": settings.environment}})
    yield
    await db_manager.close()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if not settings.is_production else None,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestLoggingMiddleware)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "type": "https://sigmaforge.dev/errors/validation-error",
                "title": "Validation Error",
                "status": 422,
                "detail": "One or more fields failed validation",
                "instance": str(request.url.path),
                "errors": exc.errors(),
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        trace_id = str(uuid.uuid4())
        logger.exception("unhandled exception", extra={"extra_fields": {"trace_id": trace_id}})
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "type": "https://sigmaforge.dev/errors/internal-error",
                "title": "Internal Server Error",
                "status": 500,
                "detail": "An unexpected error occurred",
                "instance": str(request.url.path),
                "trace_id": trace_id,
            },
        )

    app.include_router(health_router)
    app.include_router(auth_router, prefix="/api/v1")

    return app


app = create_app()
