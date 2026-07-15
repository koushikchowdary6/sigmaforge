# Release Report — SigmaForge v0.1.0

**Date:** 2026-07-14
**Milestone:** E0 (Foundations), release-audited
**Purpose of this document:** a single, honest source of truth for what
this release actually is. Every other document in this repository that
describes the full target platform now points here for current status.

## What is implemented today

- **Authentication**: login, RS256 JWT access tokens (15-minute TTL),
  rotating single-use refresh tokens with theft-reuse detection (revokes
  all sessions on replay of a revoked token), logout, logout-all, `/me`.
- **Authorization**: declarative RBAC across 5 roles (`admin`,
  `detection_lead`, `detection_engineer`, `analyst`, `researcher`),
  enforced through a single `require_permission()` dependency.
- **Security controls**: Argon2id password hashing, account lockout after
  configurable failed attempts, account-enumeration-resistant error
  responses (including a real timing-equalization mechanism, not a
  cosmetic one), security-headers middleware, RFC 7807 structured error
  responses, structured JSON request logging.
- **Database**: full 20-table production schema (`docs/DATABASE_SCHEMA.md`
  §2.1–2.19) migrated via hand-written DDL, validated against the real
  PostgreSQL grammar (`pglast`). RBAC seed data included. Only the
  `roles`, `permissions`, `role_permissions`, `users`, and `refresh_tokens`
  tables are read/written by application code today — the rest exist,
  indexed and ready, unused until their milestone.
- **Worker**: Celery app wired to Redis as broker and result backend, with
  one real diagnostic task (`ping`) proving the full round-trip.
- **Frontend**: React + TypeScript login page against the live API.
- **Infrastructure**: Docker Compose stack (postgres, redis, minio, api,
  worker, frontend) with dependency-aware healthchecks; multi-stage,
  non-root Dockerfiles for all three application services.
- **CI/CD**: GitHub Actions pipeline running lint, type-check, unit/
  integration tests, dependency vulnerability scanning (`pip-audit`,
  `npm audit`), a full `docker compose` integration boot with health-check
  polling and an API smoke test, and a Trivy container filesystem scan —
  on every pull request.
- **Documentation**: PRD, architecture, database schema, API
  specification, and threat model for the full target platform (each now
  explicitly marked with current implementation status); a formal,
  pre-registered research design for the sabotage-evaluation study;
  per-subsystem documentation for auth (`WHY`, `HOW_IT_WORKS`,
  `DESIGN_DECISIONS`, `SECURITY_ANALYSIS`, `COMMON_FAILURES`,
  `INTERVIEW_PREP`, `FUTURE_WORK`).

## What remains for E1 and beyond

Per `docs/ROADMAP.md`'s dual-track plan:

| Milestone | Scope |
|---|---|
| **E1 — Core Detection Engineering** | Sigma rule CRUD + versioning, `pySigma` schema validation, MITRE ATT&CK import and mapping, sample dataset upload, the validation engine (Sigma → SPL/EQL, sandboxed execution against samples). This is the load-bearing milestone the research track depends on. |
| **R0 — Literature Review Lock & Research Schema** | Finalize `RELATED_WORK.md` with a full (not abstract-only) read of prior work, migrate the 9 research tables (schema §2.20), author the first hand-built attack-corpus entries. |
| **E2 — Workflow, Governance & Analytics** | Rule approval state machine with self-approval prevention, full audit logging, coverage computation, false-positive reporting. Becomes the research track's human-catch-rate measurement instrument, verbatim. |
| **R1 — Attack Corpus & Model Provider Harness** | Multi-model (Claude, GPT-family, one open-weight model) adversarial rule generation at scale. |
| **R2 — Differential Verifier** | Automated ground truth for "is this rule actually sabotaged," with a manual spot-check QA pass before it's trusted. |
| **E3 — SIEM Integrations** | Real Splunk/Elastic deployment with tracked history (parallel track, no research dependency). |
| **R3 — Human Review Study & LLM-as-Judge** | The paper's core result: human catch rate and LLM-judge catch rate, both scored against R2's verified ground truth. |
| **E4 — Production AI Assistant** | AI-assisted rule drafting/refinement/alert summarization, isolated from the research harness. |
| **R4 — Analysis & Report Writing** | Statistical analysis, written technical report, self-review against fellowship-reviewer standards. |
| **E5 — Hardening** | Full threat-model pass, rate limiting, secrets management, load testing, documentation polish. |

`docs/ROADMAP.md`'s own honest estimate: 4-5 months of consistent
part-time work for the full plan — not compressible by working faster,
since corpus construction and a real human-review study are bounded by
the process itself.

## Known limitations

- Only auth and health-check functionality exists; every detection-
  engineering feature described in the PRD/API spec is designed, not built.
- No multi-factor authentication, password reset, or email verification.
- No rate limiting at the network/IP level (account lockout only protects
  a single account against brute force).
- No automated test asserting the full RBAC permission matrix cell-by-cell
  against `API_SPECIFICATION.md` §14 — today they match because both were
  authored together; that guarantee weakens on the next independent edit
  to either.
- The account-enumeration timing mitigation is implemented correctly but
  not statistically verified under load — a real, named gap, not a hidden
  one (`docs/subsystems/auth/SECURITY_ANALYSIS.md`).
- The research track has not started. No experiment has run, no rule has
  been adversarially generated, and no result — positive, negative, or
  null — exists yet. Any claim otherwise would be fabrication.

## Verification status

| Claim | How verified | Confidence |
|---|---|---|
| 20/20 backend tests pass | Actually executed (`pytest tests/ -v`), output captured | High |
| 2/2 worker tests pass | Actually executed | High |
| 2/2 frontend tests pass | Actually executed (`vitest run`) against a freshly generated, verified lockfile | High |
| `ruff`, `mypy`, `eslint`, `tsc` all clean | Actually executed, zero errors | High |
| Migration DDL is syntactically valid PostgreSQL | Parsed with `pglast` (the real PG grammar) | High — but not the same as applying it to a live database |
| Dockerfile / Compose paths all resolve correctly | Verified programmatically against the real filesystem for every `COPY`, `context`, and `dockerfile` path | High |
| `docker compose up` brings up a healthy stack end-to-end | **Not verified in this environment** — no Docker daemon in the development sandbox | **Unverified — requires user confirmation** |
| CI pipeline runs successfully on GitHub's infrastructure | **Not verified** — no push to GitHub has occurred yet from this environment | **Unverified — will be confirmed on first push** |
| No secrets committed | Repo-wide pattern search, manual review | High |
| No broken documentation links | Verified programmatically across all 20 markdown files | High |
| Documentation matches implementation | Manually cross-checked; explicit status callouts added where docs describe not-yet-built features | High |

## Deployment status

**Not deployed anywhere.** This release has not been pushed to GitHub yet
(see `PUBLISH_INSTRUCTIONS.md` for the exact manual steps — GitHub CLI was
unavailable in this environment) and has never run outside the development
sandbox. There is no live demo, no hosted instance, and no production or
staging environment. `docker compose up` against a real Docker daemon,
with a real generated JWT keypair in `.env`, is the way to run this
locally — and is the one verification step in the table above that
requires the user to confirm it firsthand.

## Overall project maturity

**Foundation-complete, feature-incomplete, by design.** This is an honest
v0.1.0: a real, tested, security-conscious authentication and
authorization core with a production-grade CI/CD pipeline sitting under a
fully designed but largely unbuilt detection-engineering platform and an
entirely unstarted research track. It is not a demo, and it is not a
finished product — it's the foundation milestone of a multi-month plan,
released at a real checkpoint with a genuine release audit behind it,
rather than held back until every future milestone is also done. The
project's own explicit standard — never claim a capability that hasn't
been implemented and evaluated — is what this report is trying to meet.
