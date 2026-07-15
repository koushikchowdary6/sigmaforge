# Contributing to SigmaForge

Thanks for your interest. This is currently a solo portfolio/research
project (see `README.md` for what stage it's at), but it's built to real
engineering standards and structured so outside contributions are possible
once the core is further along. This document describes how the project
actually works today, not aspirational process.

## Before you start

- Read `docs/PRD.md` and `docs/ROADMAP.md` first — they describe the full
  intended platform and where it's headed. `RELEASE_REPORT.md` describes
  what's actually built right now.
- Check `docs/subsystems/<name>/` if it exists for the area you're touching
  — `WHY.md` and `DESIGN_DECISIONS.md` explain intent that isn't always
  obvious from the code alone.
- Open an issue before a large PR. Small fixes (typos, obvious bugs) can go
  straight to a PR.

## Development setup

```bash
cp .env.example .env   # then fill in real values -- see README.md "Generating JWT keys"
cd infra && docker compose up --build
```

Backend (from `backend/`):

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
ruff check app/
mypy app/
pytest tests/ -v
```

Worker (from `worker/`): same pattern, `pytest tests/ -v`.

Frontend (from `frontend/`):

```bash
npm install
npm run typecheck
npm run lint
npm test
```

## Code standards

- **No placeholder implementations.** If a feature isn't ready, don't stub
  it — leave it out and track it in `ROADMAP.md`/`FUTURE_WORK.md` instead.
  This project's entire credibility rests on every claim being backed by
  real, tested code (see `RELEASE_CHECKLIST.md` for how seriously that's
  taken).
- **Every PR that touches a subsystem with a `docs/subsystems/<name>/`
  directory should update the relevant file there** — most often
  `DESIGN_DECISIONS.md` (if you made a choice worth explaining) or
  `COMMON_FAILURES.md` (if you fixed a real bug).
- **Repository pattern for anything touching the database**: business logic
  depends on a `Protocol`, never directly on SQLAlchemy. See
  `backend/app/auth/` for the reference implementation.
- **No unverified claims in commit messages, PR descriptions, or docs.** If
  you didn't run it, don't say it passes.

## Tests

New code needs tests. A bug fix needs a regression test that fails before
the fix and passes after. CI (`.github/workflows/ci.yml`) runs lint,
type-check, unit/integration tests, dependency scanning, a full
`docker compose` integration boot, and a Trivy security scan on every PR —
all of it needs to pass, not just the unit tests.

## Commit messages

Plain, descriptive, imperative mood (`Fix refresh token reuse detection`,
not `Fixed bug` or `WIP`). Reference the issue number if one exists.

## Research track contributions

The research subsystem (`docs/RESEARCH_DESIGN.md`) has additional norms
around dual-use content and pre-registration discipline — see
`docs/RESEARCH_DESIGN.md` and the research section of `docs/THREAT_MODEL.md`
before contributing corpus entries or analysis code once that track opens up
(it hasn't yet — see `ROADMAP.md` R0).

## Code of Conduct

This project follows the `CODE_OF_CONDUCT.md` in this repository.
