"""HTTP cache policy regression tests for token-bearing API responses."""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.responses import JSONResponse

from app.core.middleware import SecurityHeadersMiddleware


def test_security_middleware_disables_caching_for_success_and_error_responses():
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.post("/api/v1/auth/login")
    def login():
        # A route-level cache hint must never override the global API policy.
        return JSONResponse(
            {"access_token": "test-token", "refresh_token": "test-refresh"},
            headers={"Cache-Control": "public, max-age=3600"},
        )

    @app.post("/api/v1/auth/refresh")
    def refresh():
        return {"access_token": "rotated-test-token"}

    @app.get("/api/v1/auth/me")
    def account():
        return {"email": "test@example.invalid"}

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    with TestClient(app) as client:
        responses = [
            client.post("/api/v1/auth/login"),
            client.post("/api/v1/auth/refresh"),
            client.get("/api/v1/auth/me"),
            client.get("/healthz"),
            client.get("/missing"),
        ]

    assert [response.status_code for response in responses] == [200, 200, 200, 200, 404]
    assert all(response.headers["Cache-Control"] == "no-store" for response in responses)
