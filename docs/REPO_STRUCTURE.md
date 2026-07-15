# Repository Structure & CI/CD Strategy

**Product:** SigmaForge
**Status:** Draft v1.0 (Stage 2 deliverable: GitHub Structure + CI/CD Strategy)

---

## 1. Top-Level Layout

```
sigmaforge/
├── backend/                  # FastAPI API service
│   ├── app/
│   │   ├── auth/
│   │   ├── rules/
│   │   ├── mitre/
│   │   ├── validation/
│   │   ├── siem_integrations/
│   │   ├── ai_assistant/
│   │   ├── research/          # attack corpus, experiments, verification, human review, judge
│   │   ├── audit/
│   │   ├── reporting/
│   │   └── core/               # config, db session, security utils, middleware
│   ├── alembic/                 # migrations, one per DATABASE_SCHEMA.md section as it's implemented
│   ├── tests/
│   │   ├── unit/
│   │   ├── integration/
│   │   └── fixtures/
│   └── pyproject.toml
├── worker/                    # Celery/RQ background jobs
│   ├── jobs/
│   │   ├── validation.py
│   │   ├── deployment.py
│   │   ├── ai_generation.py
│   │   ├── experiment_orchestration.py
│   │   ├── differential_verification.py
│   │   └── coverage_snapshot.py
│   └── tests/
├── frontend/                  # React + TS + Vite
│   ├── src/
│   │   ├── features/            # one folder per domain area, mirrors backend/app/*
│   │   ├── components/
│   │   └── lib/
│   └── tests/
├── research/                   # NOT application code — the actual study artifacts
│   ├── attack_corpus/            # versioned corpus entries (data, not just DB rows — see §3)
│   ├── bypass_corpus/
│   ├── analysis/                 # notebooks/scripts implementing RESEARCH_DESIGN.md §7
│   └── report/                   # the eventual written technical report
├── infra/
│   ├── docker-compose.yml
│   ├── docker/                   # per-service Dockerfiles
│   └── terraform/                # stretch-phase AWS reference architecture
├── docs/
│   ├── PRD.md
│   ├── ARCHITECTURE.md
│   ├── DATABASE_SCHEMA.md
│   ├── API_SPECIFICATION.md
│   ├── THREAT_MODEL.md
│   ├── RESEARCH_DESIGN.md
│   ├── RELATED_WORK.md
│   ├── ROADMAP.md
│   ├── RESPONSIBLE_USE.md
│   └── subsystems/                # WHY.md / HOW_IT_WORKS.md / etc. — see §2
├── .github/
│   ├── workflows/                 # see §4
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
├── README.md
├── SECURITY.md
├── CHANGELOG.md
├── CONTRIBUTING.md
└── LICENSE
```

## 2. Per-Subsystem Documentation Convention

The mission brief asks for `WHY.md`, `HOW_IT_WORKS.md`, `DESIGN_DECISIONS.md`, `SECURITY_ANALYSIS.md`, `COMMON_FAILURES.md`, `INTERVIEW_PREP.md`, and `FUTURE_WORK.md` per major subsystem. This is a genuinely good idea — and it's Stage 4/5 output, not Stage 2/3. Writing `COMMON_FAILURES.md` for a subsystem that hasn't been built yet, or `INTERVIEW_PREP.md` for code that doesn't exist, would produce exactly the placeholder/fabricated content the mission brief explicitly forbids ("no placeholder implementations," "never claim a capability that has not been implemented"). So: the convention is defined now, populated later.

`docs/subsystems/<subsystem-name>/` is created **when that subsystem's first real milestone lands**, containing:

- `WHY.md` — the problem this subsystem solves and why it exists at all (can often be drafted from the relevant PRD/Architecture section as a starting point, then corrected against what was actually built).
- `HOW_IT_WORKS.md` — written *after* the code exists, describing what it actually does, not what was planned.
- `DESIGN_DECISIONS.md` — key choices made during implementation and why, including anywhere the implementation diverged from the design docs (divergence is normal and should be documented, not hidden).
- `SECURITY_ANALYSIS.md` — the relevant slice of `THREAT_MODEL.md`, validated against the real implementation, plus anything discovered during implementation that the threat model missed.
- `COMMON_FAILURES.md` — populated from real bugs/incidents hit during development and testing, not hypothetical ones.
- `INTERVIEW_PREP.md` — written last, once the subsystem is stable, as the teaching artifact the mission brief's "Teaching Mode" section asks for.
- `FUTURE_WORK.md` — genuine deferred scope, cross-referenced with `ROADMAP.md`.

First subsystems to get this treatment, in build order per `ROADMAP.md`: `auth`, `rules` (E1), `research/experiment-harness` (R1-R2). Not before.

## 3. Why Attack Corpus Data Lives in Two Places

`attack_corpus_entries` (database) is the operational copy the platform runs against. `research/attack_corpus/` (repo, versioned as data files — e.g., YAML or JSON, one per entry) is the source-of-record copy that gets code-reviewed like any other change, is diffable in PRs, and is what makes the study reproducible by someone who clones the repo without needing database access. A migration/seed script keeps them in sync; the repo copy is authoritative. This directly serves `RESEARCH_DESIGN.md` §7's pre-registration requirement — a corpus entry's commit timestamp is evidence it existed before results were seen.

## 4. CI/CD Pipeline Stages

Every PR runs, in order, failing fast:

1. **Lint** — `ruff` (backend/worker), `eslint` (frontend)
2. **Type check** — `mypy --strict` on backend/worker, `tsc --noEmit` on frontend
3. **Unit tests** — `pytest` (backend/worker), `vitest` (frontend); coverage threshold enforced, not just reported
4. **Dependency/security scan** — `pip-audit` + `osv-scanner` (Python), `npm audit` (frontend), container image scan (Trivy) on built images
5. **Integration tests** — spin up the full `docker-compose` stack in CI, run integration suite against it (real Postgres/Redis/MinIO, not mocks) — this is what actually proves "every milestone must compile and be deployable," not just unit-level green checks
6. **Build** — build all container images, tag with commit SHA
7. **(main branch only) Deploy gate** — manual approval required before any deploy workflow runs; no auto-deploy to a live environment without a human clicking approve, matching the platform's own "no auto-deployment of unreviewed changes" governance principle (`PRD.md` §7.5) applied to itself

Research-track CI is separate and lighter-weight: corpus data files (`research/attack_corpus/*.yaml`) are schema-validated on PR (malformed entries fail the build), and analysis scripts (`research/analysis/`) run against a small fixture dataset in CI to catch broken code — but the actual experiment matrix (§8 of `RESEARCH_DESIGN.md`) is never run in CI. It costs real money (multi-provider API calls) and produces research data, not a pass/fail signal; it's run deliberately, tracked, and its outputs are committed as data, not regenerated on every push.

## 5. Release & Versioning

- Semantic versioning for the platform (`v0.x` until E5/Hardening is complete, `v1.0` at that milestone).
- Research artifacts are versioned independently by corpus/report revision (e.g., `research-v1`, tied to a specific commit of `research/attack_corpus/` and `research/analysis/`), since the research track's "release" cadence (a completed study) doesn't match the platform's.
- `CHANGELOG.md` follows Keep a Changelog format, with a separate `research/CHANGELOG.md` for corpus/methodology changes specifically — a corpus revision after results exist is exactly the kind of change that needs its own audit trail, for the same reason `detection_rule_versions` is immutable.
