# API Specification

**Product:** SigmaForge — AI-Assisted Detection Engineering Platform
**Base URL:** `/api/v1`
**Status:** Draft v1.0 (full machine-readable spec generated at `/docs` via FastAPI/OpenAPI once implemented)

> **Implementation status:** this document specifies the full target API
> across every milestone in `ROADMAP.md` (E0–E5, R0–R4), not what exists
> today. As of the current release (E0), only **§2 Auth** and **§13 Health &
> Ops (`/healthz`, `/readyz`)** are implemented and tested. Every other
> section describes planned functionality. See `README.md`'s verification
> table and `RELEASE_REPORT.md` for exactly what is real right now.

---

## 1. Conventions

- **Auth:** All endpoints except `/auth/login`, `/auth/refresh`, and `/healthz`/`/readyz` require `Authorization: Bearer <access_token>`.
- **Content type:** `application/json` for all request/response bodies except file upload endpoints (`multipart/form-data`).
- **Pagination:** List endpoints accept `?page=1&page_size=25` (max `page_size=100`) and return:
  ```json
  { "items": [...], "page": 1, "page_size": 25, "total": 137, "total_pages": 6 }
  ```
- **Filtering/sorting:** List endpoints accept resource-specific query params (documented per-endpoint below) plus `?sort=field&order=asc|desc`.
- **Error format:** RFC 7807 `application/problem+json`:
  ```json
  {
    "type": "https://sigmaforge.dev/errors/validation-error",
    "title": "Validation Error",
    "status": 422,
    "detail": "Field 'severity' must be one of: informational, low, medium, high, critical",
    "instance": "/api/v1/rules",
    "trace_id": "a1b2c3d4"
  }
  ```
  Error responses never include stack traces, internal exception messages, or database error text (see `THREAT_MODEL.md` §5.9).
- **Rate limiting:** Enforced per-user via Redis token bucket. Standard endpoints: 120 req/min. AI endpoints: 10 req/min (configurable per role). Responses include `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`; throttled requests return `429` with `Retry-After`.
- **Idempotency:** State-changing POSTs that trigger external side effects (e.g. `deploy`) accept an optional `Idempotency-Key` header.
- **Versioning:** URL-path versioned (`/api/v1/...`); breaking changes ship as `/api/v2` with a documented deprecation window for v1.

## 2. Authentication

| Method | Path | Description | Roles |
|---|---|---|---|
| POST | `/auth/login` | Exchange email/password for access + refresh token | Public |
| POST | `/auth/refresh` | Exchange a valid refresh token for a new access/refresh pair (rotation) | Public (valid refresh token required) |
| POST | `/auth/logout` | Revoke the presented refresh token | Authenticated |
| POST | `/auth/logout-all` | Revoke all refresh tokens for the current user | Authenticated |
| POST | `/auth/mfa/enroll` | Begin TOTP MFA enrollment, returns provisioning URI | Authenticated |
| POST | `/auth/mfa/verify` | Confirm MFA enrollment with a TOTP code | Authenticated |
| GET | `/auth/me` | Current user profile + role + permissions | Authenticated |

`POST /auth/login` request:
```json
{ "email": "engineer@corp.com", "password": "...", "mfa_code": "123456" }
```
Response:
```json
{ "access_token": "...", "refresh_token": "...", "token_type": "bearer", "expires_in": 900 }
```

Note: there is no public self-registration endpoint. Users are provisioned by an Admin via `/users` — this is a deliberate control for an internal governance tool (see `THREAT_MODEL.md` §5.1).

## 3. Users & Roles (Admin)

| Method | Path | Description | Roles |
|---|---|---|---|
| GET | `/users` | List users (filter: `role`, `is_active`) | Admin |
| POST | `/users` | Create user (sends invite, no password in request) | Admin |
| GET | `/users/{id}` | Get user detail | Admin, Self |
| PATCH | `/users/{id}` | Update role/active status | Admin |
| DELETE | `/users/{id}` | Deactivate (soft) user | Admin |
| GET | `/roles` | List roles + permissions | Admin |

## 4. Detection Rules

| Method | Path | Description | Roles |
|---|---|---|---|
| GET | `/rules` | List rules (filter: `status`, `severity`, `owner_id`, `tag`, `technique_id`, `text` search) | All authenticated |
| POST | `/rules` | Create draft rule (Sigma YAML body, validated against Sigma schema synchronously) | Engineer, Lead, Admin |
| GET | `/rules/{id}` | Rule detail incl. current version, mappings, latest validation summary | All authenticated |
| PATCH | `/rules/{id}` | Update metadata (title/tags/severity) — does not touch rule body | Owner, Lead, Admin |
| POST | `/rules/{id}/versions` | Submit a new version (new Sigma YAML) — creates version N+1, status resets to `draft` if previously `approved`/`deployed` required re-approval | Owner, Lead, Admin |
| GET | `/rules/{id}/versions` | Version history | All authenticated |
| GET | `/rules/{id}/versions/{version_id}/diff` | Diff against previous version | All authenticated |
| POST | `/rules/{id}/mappings` | Attach MITRE technique IDs | Owner, Lead, Admin |
| DELETE | `/rules/{id}/mappings/{technique_id}` | Remove a mapping | Owner, Lead, Admin |
| POST | `/rules/{id}/submit-review` | Transition `draft → in_review` (requires ≥1 successful validation run on current version) | Owner |
| GET | `/rules/pending-review` | Queue of rules awaiting approval | Lead, Admin |
| POST | `/rules/{id}/approve` | Approve current version (comment required); rejects if requester == author | Lead, Admin |
| POST | `/rules/{id}/reject` | Reject with mandatory comment, status → `draft` | Lead, Admin |
| POST | `/rules/{id}/deploy` | Enqueue deployment to a named `siem_integration_id` | Lead, Admin |
| POST | `/rules/{id}/deprecate` | Retire a rule (withdraws active deployments) | Lead, Admin |

## 5. Validation

| Method | Path | Description | Roles |
|---|---|---|---|
| POST | `/rules/{id}/validate` | Enqueue a validation run (`dataset_id`, `target_backend`) | Owner, Lead, Admin |
| GET | `/validation-runs/{id}` | Poll status/results of a validation run | All authenticated |
| GET | `/rules/{id}/validation-runs` | History of validation runs for a rule | All authenticated |
| POST | `/datasets` | Upload a sample telemetry dataset (multipart, size-capped, type-checked) | Engineer, Lead, Admin |
| GET | `/datasets` | List available datasets | All authenticated |
| GET | `/datasets/{id}` | Dataset metadata (not raw content) | All authenticated |
| DELETE | `/datasets/{id}` | Remove a dataset | Uploader, Admin |

## 6. MITRE ATT&CK & Coverage

| Method | Path | Description | Roles |
|---|---|---|---|
| GET | `/mitre/techniques` | List techniques (filter: `tactic`) | All authenticated |
| GET | `/mitre/techniques/{id}` | Technique detail + mapped rules | All authenticated |
| GET | `/coverage` | Current coverage summary by tactic/technique | All authenticated |
| GET | `/coverage/history` | Coverage trend over time (from `coverage_snapshots`) | All authenticated |
| GET | `/coverage/gaps` | Techniques with zero approved+deployed coverage | All authenticated |

## 7. False Positives & Alert Investigations

| Method | Path | Description | Roles |
|---|---|---|---|
| POST | `/alerts` | Register a raw alert for investigation (from SIEM webhook or manual entry, redacted on ingest) | Analyst, Lead, Admin |
| GET | `/alerts/{id}` | Alert detail incl. AI summary if generated | All authenticated |
| POST | `/alerts/{id}/summarize` | Request an AI-generated investigation summary | Analyst, Lead, Admin |
| POST | `/rules/{id}/false-positive-reports` | Log a false-positive report against a rule | Analyst, Lead, Admin |
| GET | `/rules/{id}/false-positive-reports` | FP history for a rule | All authenticated |
| PATCH | `/false-positive-reports/{id}` | Update resolution status | Lead, Admin |

## 8. SIEM Integrations

| Method | Path | Description | Roles |
|---|---|---|---|
| GET | `/integrations` | List integrations (credentials never included in response) | Lead, Admin |
| POST | `/integrations` | Create integration (credentials write-only, encrypted server-side before persistence) | Admin |
| POST | `/integrations/{id}/test-connection` | Health check; returns boolean + latency, never echoes credentials | Admin |
| PATCH | `/integrations/{id}` | Update non-secret fields, or rotate credentials (write-only) | Admin |
| DELETE | `/integrations/{id}` | Remove integration (blocked if active deployments reference it) | Admin |
| GET | `/rules/{id}/deployments` | Deployment history for a rule | All authenticated |

## 9. AI Assistant

All AI endpoints are asynchronous (job pattern) to keep the API responsive and to allow rate limiting/backpressure independent of the LLM provider's latency.

| Method | Path | Description | Roles |
|---|---|---|---|
| POST | `/ai/generate-rule` | Body: `{ description, target_technique_id? }` → enqueues `ai_generate_rule` job, returns `job_id` | Engineer, Lead, Admin |
| POST | `/ai/refine-rule/{rule_id}` | Enqueues refinement suggestion using rule + FP history → `job_id` | Owner, Lead, Admin |
| POST | `/ai/summarize-alert/{alert_id}` | Enqueues alert summarization → `job_id` | Analyst, Lead, Admin |
| GET | `/ai/jobs/{job_id}` | Poll job status/result | Requesting user, Admin |
| POST | `/ai/refine-rule/{rule_id}/accept` | Explicitly apply a previously-returned refinement diff as a new rule version | Owner, Lead, Admin |
| GET | `/ai/recommendations` | Latest AI-generated coverage/quality recommendations (from scheduled job) | Lead, Admin |
| GET | `/ai/interactions` | Audit view of AI usage (who, what type, when, tokens) | Admin |

`POST /ai/generate-rule` response (job creation):
```json
{ "job_id": "8f1e...", "status": "queued", "poll_url": "/api/v1/ai/jobs/8f1e..." }
```
`GET /ai/jobs/{job_id}` response (completed):
```json
{
  "job_id": "8f1e...",
  "status": "succeeded",
  "result": {
    "rule_id": "c3a2...",
    "status": "draft",
    "sigma_yaml": "title: Suspicious PowerShell EncodedCommand\n...",
    "disclaimer": "AI-generated draft. Requires validation and human approval before deployment."
  }
}
```

## 10. Reporting

| Method | Path | Description | Roles |
|---|---|---|---|
| POST | `/reports/coverage` | Generate coverage report (`format=csv|pdf`), enqueues `generate_report` job | Lead, Admin |
| POST | `/reports/rule-health` | Generate rule risk/FP-rate report | Lead, Admin |
| GET | `/reports/{id}` | Poll status, returns presigned download URL when ready | Requesting user, Admin |

## 11. Research (Sabotage Evaluation) — added v1.1

All research endpoints are namespaced under `/research` and restricted to the AI Security Researcher and Admin roles unless noted. They orchestrate the same rule-generation, validation, and approval endpoints described above rather than duplicating that logic.

| Method | Path | Description | Roles |
|---|---|---|---|
| GET | `/research/mitre-techniques` | Techniques with corpus/bypass coverage counts (helps researchers find under-tested techniques) | Researcher, Admin |
| POST | `/research/attack-corpus` | Create a corpus entry (`technique_id`, `behavior_description`, `injection_channel`, `injection_payload`, `expected_blind_spot`) | Researcher, Admin |
| GET | `/research/attack-corpus` | List corpus entries (filter: `technique_id`, `injection_channel`) | Researcher, Admin |
| POST | `/research/bypass-corpus` | Create a bypass/evasion ground-truth entry for a technique | Researcher, Admin |
| GET | `/research/bypass-corpus` | List bypass entries (filter: `technique_id`) | Researcher, Admin |
| GET | `/research/model-providers` | List configured model providers (credentials never returned) | Researcher, Admin |
| POST | `/research/model-providers` | Register a model provider (credentials write-only, encrypted) | Admin |
| POST | `/research/experiments` | Enqueue an experiment matrix: `{ corpus_entry_ids[], model_provider_ids[], conditions[] }` | Researcher, Admin |
| GET | `/research/experiments/{id}` | Experiment run status incl. linked `generated_rule_version_id` once complete | Researcher, Admin |
| GET | `/research/experiments/{id}/verification` | Differential verification result for a completed run | Researcher, Admin |
| POST | `/research/human-review/sessions` | Create a blind human-review study session (`protocol_description`, `is_blind`) | Researcher, Admin |
| POST | `/research/human-review/sessions/{id}/assign` | Route completed experiment runs into the normal `/rules/pending-review` queue under this session, blinded | Researcher, Admin |
| GET | `/research/human-review/sessions/{id}/results` | Aggregated review decisions for a session, joined against `differential_verification_results` ground truth | Researcher, Admin |
| POST | `/research/experiments/{id}/judge-review` | Trigger an LLM-as-judge review of a completed experiment run | Researcher, Admin |
| GET | `/research/reports` | List generated research reports | Researcher, Admin |
| POST | `/research/reports` | Generate a research report (ASR, catch rates by defense type, cross-model breakdown) from a set of experiment runs | Researcher, Admin |
| GET | `/research/reports/{id}` | Poll/download a generated report | Researcher, Admin |
| GET | `/research/reports/{id}/raw-data` | Download the underlying raw experiment data (CSV/JSON) for independent reanalysis — this is what makes results reproducible rather than just asserted | Researcher, Admin |

`POST /research/experiments` request:
```json
{
  "corpus_entry_ids": ["c1a2...", "c1a3..."],
  "model_provider_ids": ["m-claude", "m-gpt4o", "m-llama"],
  "conditions": ["clean", "adversarial"]
}
```
Response — this fans out into `len(corpus_entry_ids) × len(model_provider_ids) × len(conditions)` individual `experiment_runs`:
```json
{ "batch_id": "b7f1...", "run_count": 12, "poll_url": "/api/v1/research/experiments?batch_id=b7f1..." }
```

Note on blinding (§ enforcement, not just policy): `POST /research/human-review/sessions/{id}/assign` inserts rows into the *same* `rule_approvals`/review-queue tables real submissions use, via the same service layer as `/rules/{id}/submit-review`. There is no separate "experiment review" endpoint a reviewer could infer is different from normal work — this is enforced by sharing code paths, not by convention.

## 12. Audit Log

| Method | Path | Description | Roles |
|---|---|---|---|
| GET | `/audit-logs` | Query audit log (filter: `user_id`, `action`, `resource_type`, `date_from`, `date_to`) | Admin |

## 13. Health & Ops

| Method | Path | Description | Roles |
|---|---|---|---|
| GET | `/healthz` | Liveness probe | Public |
| GET | `/readyz` | Readiness probe (checks DB; expands to broker/queue checks once the API depends on one — see `backend/app/api/v1/health.py`) | Public |
| GET | `/metrics` | Prometheus metrics | Internal network only (not exposed publicly) |

## 14. Authorization Matrix (Summary)

| Action | Admin | Detection Lead | Detection Engineer | Analyst | Researcher |
|---|:---:|:---:|:---:|:---:|:---:|
| Create/edit own draft rules | ✔ | ✔ | ✔ | ✘ | ✘ (writes via experiments only) |
| Submit rule for review | ✔ | ✔ | ✔ (own rules) | ✘ | ✘ |
| Approve/reject rules | ✔ | ✔ | ✘ | ✘ | ✘ |
| Deploy rules | ✔ | ✔ | ✘ | ✘ | ✘ |
| Manage SIEM integrations | ✔ | ✘ | ✘ | ✘ | ✘ |
| Manage users/roles | ✔ | ✘ | ✘ | ✘ | ✘ |
| Report false positives | ✔ | ✔ | ✔ | ✔ | ✘ |
| Use AI rule generation | ✔ | ✔ | ✔ | ✘ | ✔ |
| Use AI alert summarization | ✔ | ✔ | ✘ | ✔ | ✘ |
| View coverage dashboards | ✔ | ✔ | ✔ | ✔ | ✔ |
| View audit log | ✔ | ✘ | ✘ | ✘ | ✘ |
| Manage attack/bypass corpus, run experiments | ✔ | ✘ | ✘ | ✘ | ✔ |
| Register model providers | ✔ | ✘ | ✘ | ✘ | ✘ |
| View research reports & raw data | ✔ | ✘ | ✘ | ✘ | ✔ |

Deliberate restriction: **Researcher cannot approve or deploy rules**, even experiment-generated ones. This prevents the same person who designed an attack corpus entry from also being t