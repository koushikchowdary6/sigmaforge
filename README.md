# SigmaForge

[![CI](https://github.com/koushikchowdary6/sigmaforge/actions/workflows/ci.yml/badge.svg)](https://github.com/koushikchowdary6/sigmaforge/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/koushikchowdary6/sigmaforge)](https://github.com/koushikchowdary6/sigmaforge/releases/tag/v0.1.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**An AI-assisted detection engineering platform, and the testbed for a research question:** can adversarial context manipulation covertly sabotage LLM-generated SIEM detection rules, and does human review catch it?

This repository is under active, incremental development. Status below is accurate as of the current commit — not aspirational.

## What's actually built (Milestone E0)

- **Auth**: login, refresh-token rotation with reuse detection, logout, logout-all, RBAC (5 roles: admin, detection_lead, detection_engineer, analyst, researcher)
- **API**: FastAPI service with structured logging, security headers, RFC 7807 error responses, `/healthz` and `/readyz`
- **Worker**: Celery app wired to Redis, one real task (`ping`) proving the broker round-trip
- **Frontend**: React + TypeScript login flow against the real auth API
- **Database**: full initial migration for the production schema (19 tables, `docs/DATABASE_SCHEMA.md` §1–2.19), RBAC seed data
- **Docs**: PRD, architecture, threat model, database schema, API spec, research design, related-work literature review, roadmap — see `docs/`

**Not yet built**: detection rule authoring/validation, MITRE mapping, SIEM integrations, the AI assistant, and the research subsystem (attack corpus, differential verifier, experiment harness). These are E1 onward — see `docs/ROADMAP.md`.

## Verification status (honest, not aspirational)

This was built in a sandboxed environment without a Docker daemon or a local Postgres server available. Here's exactly what was and wasn't verified, and how:

| Check | Status | How |
|---|---|---|
| Backend unit tests (auth service logic) | ✅ Passing | `pytest`, in-memory fake repositories, 11 tests |
| Backend API tests (full HTTP request/response cycle) | ✅ Passing | `pytest` + httpx ASGI transport, dependency-injection overrides, 9 tests |
| Backend lint | ✅ Clean | `ruff check` |
| Backend type check | ✅ Clean | `mypy --strict`-equivalent config, 22 source files |
| Migration SQL syntax | ✅ Valid | All 88 DDL statements parsed successfully by `pglast` (the real Postgres grammar, not a guess) |
| Migration revision graph | ✅ Valid | `alembic history` resolves the chain correctly |
| Migration executes against a live Postgres | ⚠️ Not verified here | No Postgres server in this sandbox (no root access to install one). **Run `docker compose up` and `alembic upgrade head` yourself to confirm — see below.** |
| Worker tests | ✅ Passing | `pytest`, 2 tests including a real Celery eager-mode task execution |
| Frontend type check | ✅ Clean | `tsc --noEmit` |
| Frontend lint | ✅ Clean | `eslint` |
| Frontend component tests | ✅ Passing | `vitest` + Testing Library, 2 tests covering success and error paths |
| Frontend production build | ✅ Succeeds | `vite build` |
| Docker Compose YAML | ✅ Valid | Parsed with PyYAML |
| Every Dockerfile's build context + COPY paths | ✅ Verified | Programmatically resolved against the real filesystem, not eyeballed |
| Dockerfile best-practice linting (hadolint) | ⚠️ Not run | hadolint's release download wasn't reachable from this sandbox |
| `docker compose up` end-to-end, all services healthy | ⚠️ Not verified here | No Docker daemon in this sandbox. **This is the one thing you need to confirm yourself — see below.** CI (`.github/workflows/ci.yml`, `docker-integration` job) runs this on every PR. |

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
