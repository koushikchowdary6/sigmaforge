# SigmaForge v0.1.0 — Release Notes

**Release date:** 2026-07-14
**Milestone:** E0 (Foundations), release-audited

## What this release is

The first public release of SigmaForge, an AI-assisted detection
engineering platform being built toward a novel research contribution:
measuring whether LLM-generated Sigma detection rules can be subtly
sabotaged by adversarial context (see `docs/RESEARCH_DESIGN.md`).

This release is the foundation milestone: authentication, RBAC, the full
production database schema, a working worker and frontend skeleton, and a
CI/CD pipeline — not the detection-engineering features themselves. Read
`RELEASE_REPORT.md` for the complete, honest breakdown of what's real today
versus what's planned.

## Highlights

- JWT (RS256) authentication with rotating, hashed, single-use refresh
  tokens and theft-reuse detection
- Declarative RBAC across 5 roles, enforced through one permission-checking
  dependency — no route ever branches on a role name directly
- Argon2id password hashing with real timing-attack mitigation (not a
  hardcoded placeholder — see `docs/subsystems/auth/COMMON_FAILURES.md` for
  why that distinction mattered)
- Full 20-table production schema migrated via hand-written, `pglast`-
  validated DDL
- Celery worker proven against a real Redis broker round-trip
- React + TypeScript login flow against the live API
- Docker Compose stack (Postgres, Redis, MinIO, API, worker, frontend) with
  dependency-aware healthchecks
- GitHub Actions CI: lint, type-check, tests, dependency scanning, a full
  `docker compose` integration boot, and a Trivy security scan on every PR
- 22 automated tests (20 backend, 2 frontend), all passing; `ruff`, `mypy
  --strict`-equivalent, `eslint`, and `tsc` all clean

## What changed since the E0 build (release audit)

A release-quality audit (`RELEASE_CHECKLIST.md`) found and fixed 6 real
issues before this tag: two unused backend dependencies and a dead config
field, an unnecessary Redis dependency wired into the API container, a
missing frontend lockfile that would have broken CI on its first run, and a
genuine `npm` dependency-resolution bug surfaced while fixing that. Full
detail in `CHANGELOG.md`'s `[0.1.0]` entry.

## Known limitations

- Only auth + health-check functionality is implemented; every other
  documented feature (rule authoring, validation, SIEM integration, the
  research subsystem) is designed but not built — see `docs/ROADMAP.md`
- `docker compose up` has not been verified end-to-end by an actual Docker
  daemon (the development sandbox this was built in has none) — verified
  by other means instead (DDL parsed against the real Postgres grammar,
  every Dockerfile path resolved programmatically); see `README.md`'s
  verification-status table for exactly what was and wasn't confirmed
- No rate limiting, MFA, or password reset yet (tracked in
  `docs/subsystems/auth/FUTURE_WORK.md`)
- The research track (sabotage evaluation) has not started — this release
  is entirely the engineering foundation it depends on

## Upgrade notes

N/A — first release.

## What's next

Milestone E1 (Core Detection Engineering): Sigma rule CRUD and versioning,
schema validation via `pySigma`, MITRE ATT&CK mapping, and the validation
engine that later becomes the research track's differential verifier. See
`docs/ROADMAP.md`.

---

## Suggested GitHub repository metadata

**Description** (under 350 characters):

> AI-assisted detection engineering platform with a novel research track measuring whether LLM-generated Sigma rules can be adversarially sabotaged. FastAPI + React + Postgres, RS256 JWT auth, RBAC, full CI/CD. E0 (auth + foundations) complete and release-audited; detection engineering + research subsystem in progress.

**Topics** (20):

`detection-engineering` `sigma-rules` `mitre-attack` `siem` `security-automation`
`ai-security` `llm-security` `adversarial-ml` `prompt-injection` `fastapi`
`react` `typescript` `postgresql` `sqlalchemy` `celery` `docker`
`github-actions` `rbac` `jwt-authentication` `soc`
