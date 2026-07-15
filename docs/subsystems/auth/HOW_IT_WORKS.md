# How the Auth Subsystem Actually Works

This describes the code as built (`backend/app/auth/`, `backend/app/core/security.py`,
`backend/app/core/dependencies.py`), not the original design intent. Where it
diverges from `ARCHITECTURE.md`, see `DESIGN_DECISIONS.md`.

## Login

`POST /api/v1/auth/login` → `AuthRouter` → `AuthService.login()`
(`backend/app/auth/service.py`):

1. Look up the user by email (`UserRepository.get_by_email`).
2. If no such user exists, run `verify_password()` anyway against a
   precomputed dummy Argon2 hash (`_DUMMY_HASH`, computed once at import
   time via a real `hash_password()` call — not a hardcoded fake string).
   This keeps the response-time shape the same whether the account exists
   or not, then raises the same `InvalidCredentialsError` either way.
3. If the account is locked (`locked_until` in the future), raise
   `AccountLockedError` — a subclass of `InvalidCredentialsError` that the
   API layer maps to the identical generic message. It exists only so
   server-side logs can distinguish "wrong password" from "account locked"
   without the client being able to tell the difference.
4. If the password is wrong, call `increment_failed_login()`, which
   `UPDATE ... RETURNING`s the new count from the database (not a
   read-then-write in Python — see `COMMON_FAILURES.md` for why that
   distinction matters). If the new count reaches
   `settings.max_failed_login_attempts`, set `locked_until`.
5. On success, reset the failed-login counter and issue a token pair.

## Token issuance

`_issue_token_pair()`:

- **Access token**: JWT, RS256-signed (asymmetric — the API only needs the
  public key to verify, so a future service that only validates tokens
  never needs the private key), 15-minute default TTL, carries `sub` (user
  id) and `role`.
- **Refresh token**: a random opaque token returned to the client in the
  response body; only its SHA-256 hash is stored server-side
  (`refresh_tokens.token_hash`). The raw value is never persisted, so a
  database leak alone doesn't yield usable refresh tokens.

## Refresh (rotation + reuse detection)

`POST /api/v1/auth/refresh` → `AuthService.refresh()`:

1. Hash the presented token, look it up by hash.
2. Unknown hash → generic `RefreshTokenInvalidError`.
3. **Already revoked** → this is the reuse-detection path: revoke *every*
   active refresh token for that user and raise. The reasoning: a
   legitimate client only ever presents a token once (this same call
   revokes it and issues a new one in the same step 5 below), so a second
   presentation of an already-revoked token means two different parties
   have the same refresh token — i.e., it was stolen. Burning all sessions
   is the correct response to that signal, not a soft warning.
4. Expired → reject.
5. Otherwise: revoke the presented token and issue a brand new pair. The
   client's refresh token changes on every use (rotation) — it is never
   reused as-is.

## Logout / logout-all

`logout()` revokes the single presented refresh token (idempotent — revoking
an already-revoked token is a no-op, not an error). `logout_all()` revokes
every refresh token for the authenticated user, used for "log out of all
devices."

## RBAC enforcement

`ROLE_PERMISSIONS` (`backend/app/core/dependencies.py`) is a plain
`dict[str, set[str]]` mapping role name → permission-string set, matching
`API_SPECIFICATION.md` §14 verbatim. `require_permission("rule:approve")`
returns a FastAPI dependency that resolves the current user via
`get_current_user()`, then checks `permission_code in ROLE_PERMISSIONS[role]`
(or the `"*"` wildcard for `admin`). No route handler ever compares
`user.role.name == "admin"` directly — every authorization decision goes
through this one function, so the permission matrix has exactly one place
it can be wrong.

`get_current_user()` decodes and verifies the JWT (rejecting anything that
fails signature or expiry checks), then re-fetches the user row from the
database on every request — a revoked/deactivated user's existing
still-valid-looking access token stops working within one request of being
deactivated, because `is_active` is re-checked from the database, not from
the token's claims.

## What a request actually touches

For `GET /api/v1/auth/me`: HTTP → `AuthRouter` → `get_current_user()`
dependency → `SqlAlchemyUserRepository.get_by_id()` → Postgres, one query,
no caching layer in front of it. This is the entire round-trip; there is no
session store, no Redis-backed session cache — the JWT itself plus one DB
read is the full authentication check for every request, by design (see
`DESIGN_DECISIONS.md` on why no server-side access-token session state
exists).
