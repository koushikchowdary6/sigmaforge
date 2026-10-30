# SigmaForge

[![CI](https://github.com/koushikchowdary6/sigmaforge/actions/workflows/ci.yml/badge.svg)](https://github.com/koushikchowdary6/sigmaforge/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/koushikchowdary6/sigmaforge)](https://github.com/koushikchowdary6/sigmaforge/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**An AI-assisted detection engineering platform, and the testbed for a research question:** can adversarial context manipulation covertly sabotage LLM-generated SIEM detection rules, and does human review catch it?

This repository is under active, incremental development. **Current release: v0.1.1 (CI & runtime hardening).** Status below is accurate as of the current commit — not aspirational.

## What's actually built (E0 + initial E1 draft authoring)

- **Auth**: login, single-use refresh-token rotation with a conditional PostgreSQL consume operation (prevents two concurrent refreshes from both succeeding), reuse detection, logout, logout-all, RBAC (5 roles: admin, detection_lead, detection_engineer, analyst, researcher). Unit tests force simultaneous stale reads; this is not a claim of fully transactional session-family revocation across every possible interleaving.
- **API**: FastAPI service with structured logging, security headers, RFC 7807 error responses, `/healthz` and `/readyz`
- **E1 draft authoring**: authenticated `POST /api/v1/rules/preflight` checks bounded JSON Sigma draft structure; `POST /api/v1/rules` creates version 1 atomically. Owner-scoped `GET /api/v1/rules`, `GET /api/v1/rules/{id}`, and `PATCH /api/v1/rules/{id}` support listing, reading, and immutable versioned editing with stale-write protection. `GET /api/v1/rules/{id}/versions` returns paginated history metadata, and `GET /api/v1/rules/{id}/versions/{number}` retrieves an authorized historical snapshot. JSON is stored as a YAML 1.2-compatible representation. Current and historical reads reject malformed stored JSON or missing structural fields with a generic 404 rather than exposing a server error or producing a misleading version diff; this does not certify semantic correctness. All these routes require `rule:create` RBAC. This is **structural validation only**, not pySigma semantic validation, approval, conversion, or execution. Stored version reads also reject oversized (over 1 MiB), deeply nested, or otherwise malformed JSON snapshots with a generic not-found response, avoiding misleading version diffs or parser errors. The 1 MiB read cap leaves room for Unicode escaping of structurally valid 64 KiB write-bound drafts; it is a corruption/resource-safety guard, not a semantic validator.
- **Worker**: Celery app wired to Redis, one real task (`ping`) proving the broker round-trip
- **Frontend**: React + TypeScript login flow against the real auth API
- **Database**: full initial migration for the production schema (19 tables, `docs/DATABASE_SCHEMA.md` §1–2.19), RBAC seed data
- **Docs**: PRD, architecture, threat model, database schema, API spec, research design, related-work literature review, roadmap — see `docs/`

**Not yet built**: full pySigma semantic validation, rule approval/deployment, rule execution, MITRE mapping, SIEM integrations, the AI assistant, and the research subsystem (attack corpus, differential verifier, experiment harness). E1 remains incomplete — see `docs/ROADMAP.md`.

## Verification status (honest, not aspirational)

Local development was originally done in a sandbox without Docker/Postgres, so local verification remains intentionally separated from CI verification. GitHub Actions now runs the full container stack end to end. Here's exactly what is verified and where:

| Check | Status | How |
|---|---|---|
| Backend unit tests (auth, draft persistence, and history) | ✅ Passing | `pytest`, in-memory repositories and transaction fakes; complemented by real PostgreSQL tests |
| Backend API tests (auth, preflight, draft CRUD/history) | ✅ Passing | `pytest` + httpx ASGI transport with dependency overrides; real database behavior tested separately |
| Backend lint | ✅ Clean | `ruff check` |
| Backend type check | ✅ Clean | `mypy app/` with repository's configured rules |
| Migration SQL syntax | ✅ Valid | All 88 DDL statements parsed successfully by `pglast` (the real Postgres grammar, not a guess) |
| Migration revision graph | ✅ Valid | `alembic history` resolves the chain correctly |
| Draft create/read/edit/history against live Postgres | ✅ Passing in CI | Dedicated PostgreSQL 16 job applies Alembic migrations and exercises authenticated creation, owner-scoped reads/listing/history, immutable revisions, stale-write conflicts, foreign-key constraints, and rollback |
| Worker tests | ✅ Passing | `pytest`, 2 tests including a real Celery eager-mode task execution |
| Frontend type check | ✅ Clean | `tsc --noEmit` |
| Frontend lint | ✅ Clean | `eslint` |
| Frontend component tests | ✅ Passing | `vitest` + Testing Library, 2 tests covering success and error paths |
| Frontend production build | ✅ Succeeds | `vite build` |
| Docker Compose YAML | ✅ Valid | Parsed in repository checks; compose configuration is exercised by integration CI |
| Every Dockerfile's build context + COPY paths | ✅ Verified | Programmatically resolved against the real filesystem, not eyeballed |
| Dockerfile best-practice linting (hadolint) | ⚠️ Not run | hadolint's release download wasn't reachable from this sandbox |
| `docker compose up` end-to-end, all services healthy | ✅ Verified in CI | GitHub Actions builds/starts Postgres, Redis, MinIO, API, worker, and frontend; waits for health; then smoke-tests the API. |

## Draft rule creation (initial E1 slice)

After applying migration 0001 and obtaining a bearer access token for a user
with `rule:create` permission, submit:

```bash
curl -X POST http://localhost:8000/api/v1/rules \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"Failed logins","logsource":{"product":"windows"},"detection":{"selection":{"EventID":4625},"condition":"selection"}}'
```

A successful request returns HTTP 201 with the rule ID, rule UID, version ID,
version number 1, draft status, and `structural_only` validation level.
The database stores a rule and version together; it does not validate with
pySigma or make the rule deployable. Transaction behavior and authenticated create/read/edit/history round-trips are also verified in the dedicated migrated PostgreSQL CI job.

## Reading draft history

With the same bearer token and the UUID returned from draft creation:

```bash
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "http://localhost:8000/api/v1/rules/$RULE_ID/versions?limit=20&offset=0"
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  "http://localhost:8000/api/v1/rules/$RULE_ID/versions/1"
```

The paginated listing is ordered newest-first and returns version IDs,
numbers, current-version flags, and `has_more` **without Sigma bodies**.
The second endpoint returns the requested immutable Sigma snapshot.
Both return 404 for missing or other users' rules and require `rule:create`.
These are authoring/audit views, not semantic validation or approval.

## Running it yourself

```bash
git clone <this-repo>
cd sigmaforge
cp .env.example .env
```

Generate a real JWT keypair (used to sign access tokens):

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /tmp/jwt_private.pem
openssl rsa -pubout -in /tmp/jwt_private.pem -out /tmp/jwt_public.pem
```

Paste the contents of both files into `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` in `.env` (keep the `\n` line breaks, or use a single-line escaped form — pydantic-settings reads it as a plain string either way).

```bash
cd infra
docker compose up --build
```

Then confirm:

```bash
curl http://localhost:8000/healthz   # {"status": "ok"}
curl http://localhost:8000/readyz    # {"status": "ready", "checks": {"database": true}}
```

Apply the migration (from another terminal, once the `api` container is healthy):

```bash
docker compose exec api alembic upgrade head
```

Frontend: http://localhost:5173

## Local development (without Docker)

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest tests/ -v
ruff check app/
mypy app/

cd ../worker
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest tests/ -v

cd ../frontend
npm install
npm run typecheck
npm run lint
npm test
npm run build
```

## Documentation

| Doc | What it covers |
|---|---|
| [`docs/PRD.md`](docs/PRD.md) | Product requirements, personas, functional/non-functional requirements |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System design, component breakdown, data flows, tech justifications |
| [`docs/DATABASE_SCHEMA.md`](docs/DATABASE_SCHEMA.md) | Full ERD and DDL |
| [`docs/API_SPECIFICATION.md`](docs/API_SPECIFICATION.md) | Every endpoint, auth model, authorization matrix |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | STRIDE analysis, OWASP Top 10 mapping, dual-use/responsible-disclosure handling |
| [`docs/RESEARCH_DESIGN.md`](docs/RESEARCH_DESIGN.md) | Pre-registered hypotheses, metrics, statistics, limitations for the sabotage-evaluation study |
| [`docs/RELATED_WORK.md`](docs/RELATED_WORK.md) | Literature review and novelty positioning |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Dual-track (engineering + research) milestone plan |
| [`docs/REPO_STRUCTURE.md`](docs/REPO_STRUCTURE.md) | Folder layout, CI/CD pipeline, per-subsystem doc convention |

## License

MIT — see [`LICENSE`](LICENSE).
