# Common Failures — Auth Subsystem

Real bugs hit and fixed during E0 development, not hypothetical ones. Each
was caught by an actual test run or actual tool output, not predicted in
advance.

## 1. Off-by-one account lockout

**Symptom:** an account locked one failed attempt earlier than
`max_failed_login_attempts` should have allowed.

**Root cause:** the original `increment_failed_login()` implementation
mutated the same in-memory/ORM object the caller had already read, then the
service code read `user.failed_login_attempts` again afterward — double-
counting a single failed attempt in some code paths depending on object
identity between the read and the write.

**Fix:** changed `increment_failed_login()` to `UPDATE ... RETURNING
failed_login_attempts` and return the authoritative new count directly, so
the service never re-derives the count from a possibly-stale object.

**Lesson:** when a repository method both mutates and the caller needs the
post-mutation value, return that value from the same call. Don't mutate-
then-separately-read.

## 2. FastAPI 204 response body assertion error

**Symptom:** `/auth/logout` and `/auth/logout-all` failed at startup/test
time with "Status code 204 must not have a response body."

**Root cause:** FastAPI infers a response model from the route's return
type annotation unless told otherwise; a 204 endpoint that doesn't
explicitly disable that inference gets a default response model that
conflicts with the "no body" requirement of 204.

**Fix:** added `response_model=None` to both routes.

## 3. Dummy hash that would have defeated its own purpose

**Symptom:** none visible in normal testing — this was caught by code
review, not a failing test, which is itself the lesson.

**Root cause:** `_DUMMY_HASH` was originally a hand-typed string formatted
to *look* like an Argon2 hash (`$argon2id$v=19$...`) but not actually
produced by the Argon2 KDF. `verify_password()` against a malformed hash
fails during parsing, before any real key-derivation work happens — so the
"timing equalization" it was supposed to provide didn't exist; a
nonexistent-user login would have returned faster than a real wrong-
password check, which is the exact enumeration signal this control exists
to close.

**Fix:** compute `_DUMMY_HASH` at import time via a real `hash_password()`
call on a fixed string.

**Lesson:** a security control that "looks right" needs to be checked
against what it's actually defending against, not just that it compiles
and returns the expected error type. This class of bug doesn't show up in
functional tests at all — it would need a timing-focused test to catch
automatically, which is exactly the gap noted in `SECURITY_ANALYSIS.md`.

## 4. `/auth/me` not testable without a real database

**Symptom:** every other auth flow could be tested via
`dependency_overrides` on `get_auth_service`, but `get_current_user`
originally constructed a `SqlAlchemyUserRepository` directly inside itself,
so `/auth/me` had no seam for the integration tests to substitute a fake
repository.

**Fix:** extracted `get_user_repository()` as its own overridable FastAPI
dependency, and had `get_current_user` depend on that instead of
constructing the repository inline.

**Lesson:** "depend on an abstraction" needs to be true at every layer a
test might want to intercept, not just the outermost service call.

## 5. Import-order `NameError` in a test file

**Symptom:** a test file called `db_manager.init()` before the line that
imported `db_manager`.

**Fix:** reordered imports/setup in the test file.

**Lesson:** trivial, but worth recording because it was a real failure this
project hit, not a hypothetical — `COMMON_FAILURES.md`'s whole purpose is
to record what actually happened, including the unglamorous bugs.

## 6. Static-analysis false positives that needed explicit, documented suppressions

- **Ruff B008** flagged FastAPI's idiomatic `Depends(...)` as a default
  argument (normally a real anti-pattern: mutable default arguments). This
  is a known false positive for FastAPI's DI pattern specifically — added
  `"B008"` to the ruff ignore list in `pyproject.toml`, with a comment
  explaining why, rather than rewriting idiomatic FastAPI code to work
  around a linter.
- **mypy** flagged `Settings()` (`call-arg`) because it can't see that
  `pydantic-settings` sources required fields from environment variables
  at runtime. Suppressed with `# type: ignore[call-arg]` and an explanatory
  comment, not a blanket file-level ignore.
- **mypy** broke on `Mapped["Role"]` after ruff's `UP037` auto-fix stripped
  the quotes from a forward reference, turning a valid deferred annotation
  into a `NameError` at class-definition time. Fixed by importing `Role`
  under a `TYPE_CHECKING` guard so the forward reference resolves for mypy
  without creating a runtime circular import.

**Lesson common to all three:** every suppression here is scoped to the
specific line and explained in a comment, not a global "ignore this rule
everywhere" — a release auditor (or a future contributor) should be able to
tell instantly why each one exists.
