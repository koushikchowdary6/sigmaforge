# Architecture Walkthrough: From Browser to Stored Detection Rule

This traces the complete target request lifecycle — from a user opening
the website to a detection rule being stored — as designed across the full
roadmap (`docs/ROADMAP.md`). It is **not** a description of only what's
built today. Each section is explicitly marked **[LIVE — E0]** for what
exists and is tested right now, or **[DESIGNED — not yet built]** for what
the architecture specifies but hasn't been implemented. Mixing these
without marking them is exactly the kind of overclaiming this project's
own release audit (`RELEASE_CHECKLIST.md`) exists to catch.

## 1. Component overview

```mermaid
flowchart TB
    subgraph Client
        Browser["Browser (React + TypeScript SPA)"]
    end

    subgraph Edge
        Nginx["nginx (static file serving + reverse proxy)"]
    end

    subgraph Backend["FastAPI API service"]
        MW["Middleware: security headers, request logging"]
        Auth["Auth router"]
        Rules["Rules router (designed, E1)"]
        Deps["Dependency injection: get_current_user, require_permission"]
    end

    subgraph Data
        PG[("PostgreSQL — 20 tables")]
        Redis[("Redis — Celery broker")]
        Minio[("MinIO — object storage, designed")]
    end

    subgraph Async["Celery worker"]
        Ping["ping task (LIVE)"]
        Validation["Sigma validation job (designed, E1)"]
    end

    Browser -->|HTTPS| Nginx
    Nginx -->|static assets| Browser
    Nginx -->|/api/*| Backend
    MW --> Auth
    MW --> Rules
    Auth --> Deps
    Rules --> Deps
    Deps -->|SQL via SQLAlchemy| PG
    Backend -.->|enqueue job, designed E1+| Redis
    Async -->|consume| Redis
    Async -->|write results| PG
    Async -.->|store artifacts, designed| Minio
```

**[LIVE — E0]**: Browser → nginx → FastAPI (Auth router only) → PostgreSQL
(auth tables only). Celery worker consumes from Redis and runs one real
task (`ping`) proving the broker round-trip, but nothing in the API
currently enqueues work to it — see `docs/subsystems/auth/DESIGN_DECISIONS.md`
and `RELEASE_CHECKLIST.md` for why the API service doesn't depend on Redis
in this release.

## 2. Full request lifecycle: opening the site through a stored rule

```mermaid
sequenceDiagram
    actor User
    participant Browser
    participant Nginx
    participant API as FastAPI
    participant DB as PostgreSQL
    participant Worker as Celery Worker
    participant Redis

    Note over User,Browser: [LIVE] Page load
    User->>Browser: Navigate to site
    Browser->>Nginx: GET /
    Nginx-->>Browser: Static React app (login page)

    Note over Browser,DB: [LIVE] Authentication
    User->>Browser: Submit email + password
    Browser->>API: POST /api/v1/auth/login
    API->>API: SecurityHeadersMiddleware, RequestLoggingMiddleware
    API->>DB: SELECT user by email (case-insensitive)
    API->>API: verify_password (Argon2id) or dummy-hash timing equalization
    API->>DB: UPDATE failed_login_attempts / reset on success
    API->>API: Issue RS256 access token (15 min TTL) + opaque refresh token
    API->>DB: INSERT refresh_tokens (hash only, raw token never stored)
    API-->>Browser: 200 {access_token, refresh_token}
    Browser->>Browser: Store tokens, redirect to app

    Note over Browser,DB: [LIVE] Authenticated request
    Browser->>API: GET /api/v1/auth/me (Authorization: Bearer ...)
    API->>API: decode_access_token (verify RS256 signature + expiry)
    API->>DB: SELECT user by id (re-checks is_active every request)
    API-->>Browser: 200 {id, email, role}

    Note over Browser,DB: [DESIGNED, E1] Author a detection rule
    User->>Browser: Fill in Sigma rule editor
    Browser->>API: POST /api/v1/rules (requires rule:create permission)
    API->>API: require_permission("rule:create") via RBAC dependency
    API->>API: Validate Sigma YAML schema (pySigma)
    API->>DB: INSERT detection_rules, detection_rule_versions (status=draft)
    API-->>Browser: 201 {rule_id, version_id}

    Note over Browser,Worker: [DESIGNED, E1] Async validation
    Browser->>API: POST /api/v1/rules/{id}/validate
    API->>Redis: Enqueue validation job
    Worker->>Redis: Consume job
    Worker->>Worker: Convert Sigma -> SPL/EQL, run against sample dataset
    Worker->>DB: INSERT validation_runs (status, match results)
    Browser->>API: GET /api/v1/rules/{id}/validation-runs (poll)
    API->>DB: SELECT validation_runs
    API-->>Browser: 200 {status: succeeded, matches: [...]}

    Note over Browser,DB: [DESIGNED, E2] Approval workflow
    User->>Browser: Submit rule for review
    Browser->>API: POST /api/v1/rules/{id}/submit-review
    API->>DB: UPDATE detection_rules SET status='in_review'
    API->>DB: INSERT audit_logs (every mutating action, per THREAT_MODEL.md)
    Note right of API: A different reviewer (self-approval blocked by RBAC + business logic)
    Browser->>API: POST /api/v1/rules/{id}/approve
    API->>API: require_permission("rule:approve") + reviewer_id != owner_id check
    API->>DB: INSERT rule_approvals, UPDATE detection_rules SET status='approved'
    API->>DB: INSERT audit_logs
    API-->>Browser: 200 {status: approved}
```

## 3. Authorization: how a request is allowed or denied

```mermaid
flowchart LR
    Req["Incoming request with Bearer token"] --> Decode{"decode_access_token\n(RS256 verify)"}
    Decode -->|invalid/expired| Deny401["401 Unauthorized"]
    Decode -->|valid| Lookup["SELECT user by id from DB"]
    Lookup -->|not found or inactive| Deny401
    Lookup -->|active| Perm{"require_permission(code)\ncheck ROLE_PERMISSIONS[role]"}
    Perm -->|"code in set, or role has '*'"| Allow["Proceed to route handler"]
    Perm -->|not permitted| Deny403["403 Forbidden"]
```

The `is_active` re-check on every request (not just at token issuance) is
deliberate: a deactivated user's access is cut off within one request, even
though the JWT itself remains cryptographically valid until its 15-minute
TTL expires. Full reasoning in `docs/subsystems/auth/DESIGN_DECISIONS.md`.

## 4. Logging and observability

**[LIVE — E0]**: `RequestLoggingMiddleware` attaches a request ID
(contextvar-scoped) to every log line for the duration of a request;
`JsonFormatter` emits structured JSON logs suitable for ingestion by a real
log pipeline. `/healthz` (liveness, touches nothing) and `/readyz`
(readiness, checks the real database connection, returns 503 rather than
crashing if unreachable) are both live and tested.

**[DESIGNED, E4/E5]**: Centralized log aggregation, `/metrics` (Prometheus)
endpoint, and AI-interaction-specific audit logging (`ai_interactions`
table exists in the schema, unused until E4).

## 5. Security controls active on every request today

- `SecurityHeadersMiddleware`: sets standard hardening headers on every
  response
- RFC 7807 (`problem+json`) structured error responses — no stack traces
  or internal details leaked to the client
- CORS restricted to the configured frontend origin (dev default:
  `http://localhost:5173`)
- Every route requiring authentication goes through the same
  `get_current_user` → `require_permission` chain — there is exactly one
  place authorization logic lives, not one per route

## What this walkthrough is not

It is not a claim that rule authoring, validation, or approval work today
— they're marked **[DESIGNED]** above precisely because they don't. See
`RELEASE_REPORT.md` for the complete, current-state answer to "what is
implemented today."
