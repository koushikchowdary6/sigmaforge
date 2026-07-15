# Security Analysis — Auth Subsystem

Cross-referenced against `THREAT_MODEL.md` §4 (Authentication & Session
Management). This is the STRIDE-relevant slice of that document, validated
against what was actually built, plus anything found during implementation
that the threat model didn't anticipate.

## Controls implemented and verified

| Threat | Control | Verified by |
|---|---|---|
| Account enumeration via login error messages | Generic `InvalidCredentialsError` for nonexistent user, wrong password, and inactive account alike | `test_login_nonexistent_user_same_error_as_wrong_password` |
| Account enumeration via response timing | Real Argon2 hash computed against a fixed dummy value when the user doesn't exist, so timing is equivalent to a real failed check | Manual code review; not load-tested for statistical timing equivalence (see Limitations) |
| Credential stuffing / brute force | Lockout after `max_failed_login_attempts`, for `lockout_duration_seconds` | `test_account_locks_after_max_failed_attempts`, `test_lockout_resets_on_successful_login` |
| Refresh token theft (passive, e.g. log/database exposure) | Only SHA-256 hash stored server-side; raw token never persisted | Code review of `repository_sqlalchemy.py` — no raw-token column exists in the schema |
| Refresh token theft (active reuse) | Reuse of an already-revoked token revokes all sessions for that user | `test_refresh_reuse_detected_burns_all_sessions` |
| Token forgery | RS256 asymmetric signing; verification only needs the public key | `test_refresh_unknown_token_rejected`; JWT signature is checked by `pyjwt`, not hand-rolled |
| Privilege escalation via role tampering | Role is read from the database on every request (via `get_current_user` → `user.role`), never trusted from client input or cached in a way that survives a role change | Code review of `dependencies.py` |
| Deactivated user retaining access | `is_active` re-checked from the database on every request | Code review; no automated test for "deactivate user mid-session" yet (see gap below) |
| Privilege boundary between roles | `require_permission()` checked against `ROLE_PERMISSIONS`, single source of truth | Manual review against `API_SPECIFICATION.md` §14; no automated test yet asserting the full permission matrix cell-by-cell (see gap below) |

## Gaps found during implementation that the threat model didn't call out

- **Timing-equalization is untested, not just unverified.** The threat
  model names "account enumeration via timing side-channel" as a risk and
  the code has a real mitigation, but there is no test in this repository
  that actually measures response-time distributions for existing vs.
  nonexistent users. Claiming the mitigation is *effective* without that
  measurement would be exactly the kind of unverified capability claim
  this project's own rules forbid. What's true today: the mitigation is
  implemented correctly in code (real hash computation, not a shortcut);
  what's not yet true: statistical proof it closes the timing gap under
  realistic load. Tracked in `FUTURE_WORK.md`.

- **No automated full-matrix RBAC test.** Unit tests cover individual
  auth-service behaviors, but there is no test that iterates every
  `(role, permission)` pair in `ROLE_PERMISSIONS` against
  `API_SPECIFICATION.md` §14 and fails if they drift apart. Today they
  match because both were authored together in this milestone; that
  guarantee weakens the moment either file is edited without the other.
  This is a real, fixable gap — tracked in `FUTURE_WORK.md`, not deferred
  indefinitely.

- **No rate limiting yet at the network/endpoint level.** Account lockout
  protects a single account from brute force, but nothing yet throttles
  request volume from a single IP across many accounts (a distributed
  credential-stuffing pattern). `THREAT_MODEL.md` and `ROADMAP.md` (E5
  Hardening) both already scope this correctly as later work; noted here
  so it isn't accidentally assumed to already exist.

## Deliberately out of scope for E0 (not gaps — scoped decisions)

- Multi-factor authentication
- Password reset / email verification flows
- Session/device management UI (revoking a single named session by device)
- SSO / OAuth federation
- Access-token denylist for instant revocation (see `DESIGN_DECISIONS.md`)

These are listed in `FUTURE_WORK.md` with the milestone they're expected to
land in, where known.
