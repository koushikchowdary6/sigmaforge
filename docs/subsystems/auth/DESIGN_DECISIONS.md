# Design Decisions

## RS256 over HS256

HS256 uses one shared secret for both signing and verifying — any service
that can verify a token can also forge one. RS256 splits this: the API
holds the private key and signs; anything that only needs to verify tokens
(a future gateway, the worker if it ever needs to check a token) only needs
the public key. Cost: RS256 is slower and the keys are bigger to manage
(`.env` needs a full PEM keypair, not a short string). For a platform whose
entire threat model is "can this token be forged or replayed," that
trade-off is worth it from day one — retrofitting asymmetric signing after
services depend on shared-secret verification is a much bigger migration
than the up-front key-management cost.

## Repository pattern (Protocol + SQLAlchemy impl + in-memory fake)

`app/auth/repository.py` defines `UserRepository`/`RefreshTokenRepository`
as `typing.Protocol`s. `repository_sqlalchemy.py` implements them against
real Postgres; `tests/fixtures/fake_repository.py` implements them in
memory. `AuthService` depends only on the Protocol, never on SQLAlchemy
directly.

This is why `tests/unit/test_auth_service.py`'s 11 tests run without a
database at all, in well under a second, while still exercising the exact
same `AuthService` class production traffic goes through — not a simplified
copy of it. The alternative (mock the ORM session directly) tests
SQLAlchemy's behavior more than the service's logic and breaks on every
unrelated schema change.

## Declarative permission strings, not role-name comparisons

`ROLE_PERMISSIONS: dict[str, set[str]]` plus a single `require_permission()`
checker was chosen over scattering `if user.role.name in ("admin",
"detection_lead"):` checks through route handlers for one reason: the
permission matrix in `API_SPECIFICATION.md` §14 is the actual source of
truth for who can do what, and it needs to be *checkable* against the code —
one dict, diffable against one table — not re-derived by reading every
route handler. It also means adding a new role never requires touching
route-handler code, only this one mapping.

## Rotating, hashed, single-use refresh tokens with reuse detection

Three separate decisions bundled into one mechanism:

- **Hashed at rest** (SHA-256 of the raw token, only the hash stored): a
  database dump alone doesn't yield usable refresh tokens.
- **Rotated on every use**: limits the blast radius of a stolen-but-not-yet-
  used token to a single refresh cycle.
- **Reuse detection burns all sessions**: chosen over silently ignoring
  the reuse or just rejecting it, because a second presentation of an
  already-consumed token is a strong signal that two parties now hold what
  should have been a single-use secret — logging the user out everywhere
  is the conservative response to a signal that specific.

## Argon2id, not bcrypt

Argon2id was the PHC (Password Hashing Competition) winner and is
specifically designed to resist both GPU-cracking and side-channel/timing
attacks better than bcrypt. `argon2-cffi`'s defaults were used rather than
hand-tuned cost parameters — tuning Argon2 parameters requires benchmarking
against real production hardware, which doesn't exist yet for a project at
this stage; `needs_rehash()` already exists in `security.py` specifically so
parameters can be strengthened later without a forced mass password reset.

## A real dummy hash for timing equalization, not a fake string

Early in development, `_DUMMY_HASH` was a hand-typed string made to *look*
like an Argon2 hash. It doesn't work: `verify_password()` against a
malformed hash fails at the parsing step, near-instantly, which defeats the
entire point of timing equalization (the real check for an existing user
with a wrong password takes measurably longer, because it actually runs the
Argon2 KDF). The fix was to compute `_DUMMY_HASH` once, at import time, via
a real call to `hash_password()`. This is covered in more detail in
`COMMON_FAILURES.md` because it's the kind of bug that looks correct at a
glance and only fails under actual timing measurement.

## No server-side access-token session state

Access tokens are stateless JWTs with a short (15-minute) TTL — there is no
database table or cache tracking "currently valid access tokens." This
trades instant revocation (an admin cannot invalidate one specific access
token before it expires) for simplicity and one fewer moving part in E0.
The mitigation is the short TTL plus the fact that `is_active` is re-checked
from the database on every request via `get_current_user()` — deactivating
a user takes effect within one request, even though a still-unexpired JWT
technically remains cryptographically valid. Refresh tokens, by contrast,
are fully revocable because they're checked against the database on every
use. Instant access-token revocation (a denylist) is tracked as future work
if a real incident ever demands it.

## Divergence from `ARCHITECTURE.md`

None of substance for E0. The design docs described this subsystem at a
level (login, refresh, RBAC, audit-log-ready) that the implementation
matches. The one true divergence is scope, not design: `researcher` role
permissions exist in `ROLE_PERMISSIONS` (per `ROADMAP.md`'s explicit
instruction to seed it now even though unused until the research track)
but nothing in E0 currently authenticates as that role in practice — it is
inert but present and tested-for-non-regression via the RBAC unit tests.
