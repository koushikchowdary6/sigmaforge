# Changelog

All notable changes to this project are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

Nothing yet. Next up is Milestone E1 (Core Detection Engineering) per `docs/ROADMAP.md`.

## [0.1.0] - 2026-07-14 - Milestone E0 (Foundations) + Release Audit

### Added
- Repository scaffolding per `docs/REPO_STRUCTURE.md`
- Backend: FastAPI app with structured JSON logging, security headers middleware, RFC 7807 error responses, `/healthz` and `/readyz`
- Auth domain: login, refresh-token rotation with reuse detection, logout, logout-all, `/me`, RBAC (5 roles)
- Repository pattern (abstract interfaces + SQLAlchemy implementation + in-memory fakes for testing) for the auth domain
- Initial database migration: full production schema (19 tables), RBAC seed data
- Worker: Celery app wired to Redis, `ping` diagnostic task
- Frontend: React + TypeScript login flow against the real auth API
- Docker Compose stack: postgres, redis, minio, api, worker, frontend, with healthchecks
- CI workflow: lint, type-check, test, dependency scan, and full docker-compose integration check for all three services
- Documentation set: PRD, architecture, database schema, API spec, threat model, research design, related-work review, roadmap

### Fixed (during development, documented for transparency)
- `AuthService.login`'s failed-login-count check was double-counting the increment already applied by the repository, causing account lockout after N-1 failures instead of N — fixed by having the repository return the authoritative post-increment count rather than the caller re-deriving it from a possibly-shared object reference
- `docs/PRD.md` / `docs/ARCHITECTURE.md` originally scored the automated differential verifier as a peer "defense" alongside human review, which is circular since the verifier also establishes ground truth — corrected in v1.2 of those docs and `docs/RESEARCH_DESIGN.md` §1
- Frontend Docker build context was scoped to `frontend/` alone, which cannot reach `infra/docker/nginx.conf` — widened to the repo root for that one service

### Fixed (release audit, before v0.1.0 publication — see `RELEASE_CHECKLIST.md`)
- Removed unused `redis` and `python-multipart` dependencies from `backend/requirements.txt` (zero imports anywhere in `app/`); they'll return when E1/E4 actually need them
- Removed the dead `Settings.redis_url` config field (defined, never read)
- Removed the `api` Docker Compose service's unnecessary `depends_on: redis` and unused `REDIS_URL` env var — the backend doesn't talk to Redis in E0, only the worker does
- Wired the already-installed `eslint-plugin-react-hooks` into `.eslintrc.cjs` (it was present in `package.json` but never enabled)
- Generated and committed `frontend/package-lock.json`, which had never existed — `ci.yml`'s `cache-dependency-path` was pointing at a file that didn't exist
- Fixed a real `npm` dependency-resolution crash (`Invalid Version` from an `aria-query` version conflict between `@testing-library/dom` and other testing-library packages) surfaced while generating that lockfile, via a `package.json` `overrides` pin
- Corrected `docs/API_SPECIFICATION.md`'s claim that `/readyz` checks "DB/Redis" — it has only ever checked the database
- Added explicit "implementation status" notes to `PRD.md`, `ARCHITECTURE.md`, `DATABASE_SCHEMA.md`, `API_SPECIFICATION.md`, and `THREAT_MODEL.md` distinguishing the full target design (what these documents describe) from what's actually built today (E0 only)
- Added `docs/subsystems/auth/` (`WHY.md`, `HOW_IT_WORKS.md`, `DESIGN_DECISIONS.md`, `SECURITY_ANALYSIS.md`, `COMMON_FAILURES.md`, `INTERVIEW_PREP.md`, `FUTURE_WORK.md`), fulfilling `docs/REPO_STRUCTURE.md`'s per-subsystem documentation convention now that auth's first milestone has landed

## Versioning

Pre-1.0. See `docs/ROADMAP.md` for the milestone plan; this file will start following semantic versioning at the `v1.0` tag (post E5/Hardening). `v0.1.0` marks the first public release (E0 complete + release audit passed), not a claim of production readiness.
