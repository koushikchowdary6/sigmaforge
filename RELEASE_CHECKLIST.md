# Release Checklist — v0.1.0 (E0)

Audit performed before the first public release. Every item below was
checked against the real repository state (grep/programmatic verification
or an actually-executed command), not assumed. Issues found were fixed and
re-verified, not just logged.

| # | Check | Result | Notes |
|---|---|---|---|
| 1 | No secrets or API keys committed | ✅ PASS | Repo-wide grep for key/secret/password/token patterns found nothing real; only placeholders in `.env.example`. |
| 2 | `.env` is ignored | ✅ PASS | `.gitignore` covers `.env`, `*.pem`; no `.env` file exists in the tree. |
| 3 | `node_modules`, caches, build artifacts, venvs ignored | ✅ PASS | `.gitignore` covers all of them; confirmed every stray cache/artifact directory currently on disk (leftovers from sandbox development) matches an ignore rule. |
| 4 | Documentation reflects the actual implementation | ⚠️ FOUND → ✅ FIXED | `PRD.md`, `ARCHITECTURE.md`, `DATABASE_SCHEMA.md`, `API_SPECIFICATION.md`, `THREAT_MODEL.md` describe the full target platform without distinguishing "built today" from "planned." Added an explicit **Implementation status** callout to each, stating exactly what exists now and pointing to `RELEASE_REPORT.md`. |
| 5 | No README claims about unimplemented features | ✅ PASS | `README.md`'s verification table was already scoped to what's real; no changes needed there. |
| 6 | No placeholder implementations | ✅ PASS | Searched for TODO/FIXME/stub/`NotImplementedError`/etc. — only found honest comments *explaining* why no stub exists (a deliberate anti-placeholder choice), not actual placeholder code. |
| 7 | No dead code | ⚠️ FOUND → ✅ FIXED | `Settings.redis_url` was defined but never read anywhere in the backend. Removed. |
| 8 | No unused dependencies | ⚠️ FOUND → ✅ FIXED | Backend: `redis` and `python-multipart` were listed in `requirements.txt` with zero imports anywhere in `app/`. Removed (they'll return in E1/E4 when the backend actually enqueues jobs and accepts file uploads). Frontend: `eslint-plugin-react-hooks` was installed but never enabled in `.eslintrc.cjs`. Wired it in via `plugin:react-hooks/recommended` rather than deleting a genuinely useful lint rule. |
| 9 | All links valid | ✅ PASS | Programmatically checked every relative markdown link across all 20 `.md` files in the repo — zero broken links. |
| 10 | Dockerfiles reference correct paths | ✅ PASS | Programmatically resolved every `build.context` / `build.dockerfile` / `COPY` source against the real filesystem for all three Dockerfiles — all correct. (The frontend Dockerfile intentionally uses a repo-root build context because it needs `infra/docker/nginx.conf`, outside `frontend/`.) |
| 11 | GitHub Actions reference existing files | ⚠️ FOUND → ✅ FIXED | `ci.yml`'s frontend job set `cache-dependency-path: frontend/package-lock.json`, but no lockfile had ever been committed — this would fail the job immediately on `actions/setup-node`. Generated a real lockfile. Doing so also surfaced a genuine `npm` dependency-resolution bug (an `aria-query` version conflict between `@testing-library/dom` and other testing-library packages caused `npm install`/`npm ci` to crash with `Invalid Version`); fixed with a `package.json` `overrides` pin, then re-verified `tsc`, `eslint`, and `vitest` all still pass clean against the new lockfile. |
| 12 | Diagrams match the implementation | ✅ FIXED (via #4) | `ARCHITECTURE.md`'s and `ROADMAP.md`'s Mermaid diagrams describe the target system; the new implementation-status callouts make clear which parts are built vs. planned so the diagrams aren't mistaken for current state. |
| 13 | Every documented API endpoint exists | ✅ PASS (scoped) | `API_SPECIFICATION.md` is the full target spec by design (now stated explicitly). Of the endpoints it marks as implemented today (Auth §2, Health §13), every one exists in code and matches — verified by diffing the route list against the spec. Found and fixed one factual error: the spec claimed `/readyz` checks "DB/Redis"; the code only ever checked the database. |
| 14 | Every database migration represented in schema doc | ✅ PASS | Programmatically matched all 20 `CREATE TABLE` statements in `0001_initial_schema.py` against `DATABASE_SCHEMA.md` §2.1–2.19 — exact 1:1 correspondence (§2.2 documents two closely related tables, `permissions` and `role_permissions`, together). Confirmed the 9 research tables (§2.20) are correctly *not* yet migrated, per `ROADMAP.md`'s R0 milestone. |
| 15 | Docker Compose service dependencies are accurate | ⚠️ FOUND → ✅ FIXED (not in original checklist, found during audit) | The `api` service declared `depends_on: redis` and set an unused `REDIS_URL` env var, even though the backend never talks to Redis in E0 — only the worker does. This both slowed container startup for no reason and misrepresented the architecture. Removed both; documented why in a code comment. |
| 16 | Per-subsystem documentation convention honored | ⚠️ FOUND → ✅ FIXED (not in original checklist, found during audit) | `docs/REPO_STRUCTURE.md` commits to writing `WHY.md` / `HOW_IT_WORKS.md` / `DESIGN_DECISIONS.md` / `SECURITY_ANALYSIS.md` / `COMMON_FAILURES.md` / `INTERVIEW_PREP.md` / `FUTURE_WORK.md` once a subsystem's first real milestone lands — auth's did, with E0's approval, and the docs didn't exist yet. Written now, grounded in the actual implementation and its real bugs, at `docs/subsystems/auth/`. |

## A note on file integrity

During this audit, a sandbox filesystem quirk was caught and fixed: several
files edited earlier in this session (`backend/requirements.txt`,
`backend/app/core/config.py`, `infra/docker-compose.yml`) intermittently
picked up trailing NUL-byte padding or truncation when copied/read across
the two filesystem views this environment exposes. This was caught by
re-reading every edited file byte-for-byte after editing, not by trusting
tool success responses. All affected files were rewritten and confirmed
stable across multiple independent reads, and a full repository sweep
confirmed no other file is affected. This is disclosed here in the interest
of the same honesty standard the rest of this project holds itself to —
it's an environment artifact, not a code defect, but it did require real
verification work to rule out.

## Outcome

16 checks run, 6 real issues found, all 6 fixed and re-verified (backend:
20/20 tests, ruff, mypy all clean; frontend: tsc, eslint, vitest all clean
against the newly-committed lockfile). Full detail in `RELEASE_REPORT.md`.
