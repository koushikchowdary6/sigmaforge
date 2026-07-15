# Portfolio Case Study: SigmaForge

**Status at time of writing:** v0.1.0, milestone E0 (Foundations) complete
and release-audited. This case study is written to that honest scope —
it does not describe finished detection-engineering features or research
results, because neither exists yet.

## Problem

Detection engineering teams increasingly use LLMs to help draft Sigma
rules — turning a threat-intel report or an incident writeup into a
detection rule faster than a human would alone. That's a real
productivity win, and most tooling in this space (Sublime Security's
evaluation framework, CTI-REALM, GenTI) measures how *good* those
LLM-generated rules are under clean, cooperative conditions.

None of the published work I could find asks the adjacent question: what
happens when the input isn't cooperative? If an attacker can influence the
threat-intel report or the false-positive comment an LLM sees while
drafting a rule, can they steer it toward a rule with a specific blind
spot — one that still looks reasonable enough to pass a normal human
review? That gap is the reason this project exists in its current form,
rather than as a more conventional "AI-assisted SOC tool."

## Motivation

I wanted a portfolio project that was honest about being a *research*
contribution, not just a demonstration of backend engineering skill. That
meant designing the study before writing implementation code: identifying
what question existing literature (Anthropic's sabotage evaluations and
SHADE-Arena, the three papers above) doesn't answer, writing a
pre-registered research design with falsifiable hypotheses, and — the part
I take the most pride in — catching and fixing a real methodological bug
in my own early draft, where the automated verifier that would establish
ground truth was also being scored as a peer "defense" alongside human
review. That's circular: you can't use the same instrument to define
correctness and to measure how well something else detects
correctness. Fixing that before any code was built is documented in
`docs/RESEARCH_DESIGN.md` and `CHANGELOG.md`.

## Architecture

SigmaForge is a monorepo: a FastAPI backend, a Celery worker, a
React/TypeScript frontend, and PostgreSQL, orchestrated with Docker
Compose. The database schema is built to serve two purposes from one
source of truth — the same `detection_rules` / `detection_rule_versions` /
`rule_approvals` tables the production platform uses are what the research
track's differential verifier and human-review study will run against
later, rather than a simulated/duplicate schema. See
`docs/ARCHITECTURE_WALKTHROUGH.md` for a full request-by-request trace of
what's built today, with diagrams.

Two design choices anchor the backend: a repository pattern (Protocol
interfaces, a real SQLAlchemy implementation, and in-memory fakes for
testing) that keeps business logic testable without a database, and
declarative RBAC (a single permission-checking dependency, never a route
that branches on role name directly) enforcing the platform's authorization
matrix from one place.

## Challenges

**A real methodological bug, not a coding bug.** The circularity issue
described above — scoring the ground-truth instrument as a peer defense —
was the hardest problem in the project so far, and it wasn't a bug I could
find by running tests. It required stepping back from the schema and
asking what each measurement was actually independent of.

**Development-environment constraints that mirror real production
constraints.** The environment I built this in had no Docker daemon, no
root access, and a filesystem quirk where certain files became silently
corrupted or unable to be deleted after creation. Rather than paper over
that, I built verification methods that didn't depend on the missing
capability — parsing the database migration's DDL against the real
PostgreSQL grammar (`pglast`) instead of just eyeballing it, and
programmatically resolving every Dockerfile `COPY` path against the actual
filesystem instead of assuming `docker build` would catch a mistake. That
approach caught a real bug: the frontend Dockerfile's build context
couldn't reach a file it needed.

**Not overclaiming.** The single hardest discipline throughout was
keeping documentation honest about what's built versus designed. The
release audit before this tag added explicit "implementation status"
notes to every design document for exactly this reason — a full
target-platform spec written before the platform exists is normal and
useful, but only if it's never mistaken for a status report.

## Security Decisions

- **RS256 over HS256** for JWT signing: asymmetric verification means a
  future service that only needs to *validate* tokens never needs the
  private key.
- **Rotating, hashed, single-use refresh tokens with reuse detection**:
  presenting an already-revoked token is treated as evidence of theft and
  burns every active session for that user, not just a soft warning.
- **A real dummy-hash timing mitigation, not a fake one.** An early
  version of the login flow used a hand-typed string that merely *looked*
  like an Argon2 hash for timing-equalization on nonexistent-user login
  attempts. It failed instantly at the parsing step, defeating its own
  purpose. Fixed by computing a real hash at import time. Full writeup in
  `docs/subsystems/auth/COMMON_FAILURES.md`.
- **Declarative RBAC as a single source of truth**, checked against the
  documented authorization matrix rather than re-derived by reading route
  handlers.

## Testing Strategy

20 backend tests (11 unit, against `AuthService` via in-memory fake
repositories — no database required; 9 integration, against the real
FastAPI app via `ASGITransport` with dependency overrides) plus 2 frontend
tests. All passing, `ruff`/`mypy`/`eslint`/`tsc` all clean — verified by
actually running each command and reading its output, not asserted from
memory. Three real bugs were caught during development this way (a
failed-login-count double-increment, a FastAPI 204-response assertion
error, and the dummy-hash issue above) — documented, not hidden, in
`docs/subsystems/auth/COMMON_FAILURES.md`. CI runs the same suite plus a
full `docker compose` integration boot and a Trivy container scan on every
PR.

## Research Direction

The research track (not yet started — see Future Work) is designed around
four falsifiable hypotheses about whether adversarial context measurably
increases the rate of exploitable blind spots in LLM-generated Sigma
rules, evaluated with Wilson score confidence intervals and Holm-Bonferroni
correction for multiple comparisons, against a corpus of roughly 60-80
hand-and-model-constructed attack scenarios across at least 15 MITRE
ATT&CK techniques. Full detail, including the explicit failure-mode
criteria that are distinct from hypothesis falsification (an underpowered
sample isn't the same thing as a null result), is in
`docs/RESEARCH_DESIGN.md`.

## Future Work

Per `docs/ROADMAP.md`: E1 (Sigma rule authoring, `pySigma` validation,
MITRE mapping, the validation engine that later becomes the differential
verifier), E2 (approval workflow, audit logging, coverage analytics), R0-R4
(the actual research track), E3 (SIEM integrations), E4 (production AI
assistant features), and E5 (hardening). The honest timeline estimate in
`docs/ROADMAP.md` is 4-5 months of consistent part-time work for the full
dual-track plan — deliberately not compressed, since corpus construction
and an honest human-review study are bounded by the process itself, not by
typing speed.
