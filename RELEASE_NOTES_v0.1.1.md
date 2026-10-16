# SigmaForge v0.1.1 — CI & Runtime Hardening

This patch release keeps the project at **Milestone E0 (Foundations)** and packages the reliability/security work completed after v0.1.0. It does **not** claim E1 detection-authoring or research features that are not built yet.

## Highlights

- Full GitHub Actions pipeline is green across backend, worker, frontend, security scan, and Docker integration.
- Docker integration now builds and starts the complete stack and verifies every service becomes healthy before smoke-testing the API.
- Backend and worker dependency vulnerability scans pass after dependency upgrades.
- Frontend container build and health-check issues uncovered by CI were fixed.
- MinIO integration uses an available pinned release image instead of a broken `latest`/invalid tag.
- Engineering tradeoffs and implementation limitations are documented more explicitly.

## Important fixes since v0.1.0

- Updated FastAPI/PyJWT dependency chain to clear reported Python dependency CVEs.
- Corrected the Trivy Action version and added worker dependency scanning.
- Fixed frontend Vite/Vitest configuration so Docker's `tsc -b` build succeeds.
- Fixed frontend container health checks by handling IPv4/IPv6 localhost behavior correctly.
- Repaired MinIO image selection in Docker integration.
- Added and refined engineering-decision documentation without overstating unbuilt features.

## Verified in CI

The release commit is expected to pass:

- backend: ruff, mypy, pip-audit, unit/API tests
- worker: ruff, pip-audit, tests
- frontend: type-check, eslint, tests, production build, npm audit
- Trivy filesystem security scan
- Docker integration: full stack build/start, health checks, API smoke test

## Still not built

Detection rule authoring/validation, MITRE mapping, SIEM integrations, the AI assistant, and the research experiment subsystem remain future milestones. See `docs/ROADMAP.md`.

This is a maintenance/hardening release, not a production-readiness claim.
