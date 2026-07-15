# Interview Prep — Auth Subsystem

Deep-dive questions specific to this subsystem (see the top-level interview
prep material for platform-wide questions). Written last, once the
subsystem was stable, as a teaching artifact — the point is to explain
what was actually built and why, not to rehearse a generic answer.

**Q: Why rotate refresh tokens instead of just giving them a long TTL and
leaving them alone?**
A static, long-lived refresh token is a single high-value secret that, if
stolen, is usable for its entire TTL with no way to distinguish the
attacker's use from the legitimate user's. Rotation means every use
invalidates the token that was just presented — so a legitimate client and
an attacker holding a copy of the same token will collide on the very next
refresh, which is detectable (see reuse detection) instead of silently
allowing both indefinitely.

**Q: Walk me through what happens if an attacker steals a refresh token
and uses it before the legitimate user does.**
The attacker's refresh succeeds — the service can't yet tell attacker from
owner. But that call consumes and revokes the original token and issues a
new one to whoever called it (the attacker). When the legitimate user's
client later tries to use its now-stale copy of the original token, that
token is already revoked — hitting the reuse-detection branch — and the
service revokes every active refresh token for that user, forcing
everyone, including the attacker, to re-authenticate. The detection window
is exactly one refresh cycle; it does not prevent the first fraudulent use,
only limits how long it persists.

**Q: Why store a hash of the refresh token instead of the token itself?**
So that a database compromise (backup leak, SQL injection read, insider
access) doesn't hand over usable credentials. Hashing is one-way; even with
full read access to `refresh_tokens`, an attacker cannot reconstruct a
token that would pass the hash check.

**Q: Why SHA-256 for the refresh token hash but Argon2id for the password
hash — isn't that inconsistent?**
No — they defend against different things. Passwords are low-entropy,
human-chosen secrets that must resist offline brute-force/dictionary
attacks, which is exactly what Argon2id (deliberately slow, memory-hard) is
for. Refresh tokens are high-entropy, randomly generated values with no
guessable structure; a fast hash is fine because there's no dictionary to
brute-force against — the token space itself is the defense. Using Argon2
for the refresh token would only add unnecessary latency to every
authenticated request's session lookup with no security benefit.

**Q: Why does `get_current_user` re-fetch the user from the database on
every request instead of trusting the JWT claims?**
The JWT's `role` claim was correct at the moment the token was issued but
can go stale — if an admin demotes or deactivates a user mid-session, a
still-unexpired access token would otherwise keep working with outdated
authority for up to its full 15-minute TTL. Re-checking `is_active` (and,
implicitly, current role) from the database on every request closes that
gap at the cost of one extra query per request — an explicit trade-off
documented in `DESIGN_DECISIONS.md`.

**Q: What's the actual security value of the RS256 vs. HS256 choice, given
this is currently a single monolithic API service that both signs and
verifies?**
Today, with one service, the practical difference is small — the same
process holds both keys. The value is architectural: the moment a second
service needs to verify tokens (a gateway, a future microservice split),
RS256 lets that service hold only the public key, so a compromise of that
second service can't be used to forge tokens. Choosing RS256 now avoids a
signing-scheme migration later, which is a much more disruptive change
than the up-front cost of managing an RSA keypair.

**Q: This project claims "no placeholder implementations." How do you know
the auth subsystem doesn't have any?**
Every claim in `README.md`'s verification table is backed by an actually-
executed command with shown output — 20 backend tests passing, `mypy`
clean, `ruff` clean — not asserted from memory. The three real bugs in
`COMMON_FAILURES.md` are evidence the tests are doing real work: they
caught real defects (the lockout off-by-one, the FastAPI 204 issue, the
non-testable `/auth/me` dependency), which a placeholder or untested
implementation would not have surfaced.

**Common follow-up:** "What would you do differently with more time?" —
answer honestly from `FUTURE_WORK.md`: add the timing-side-channel
measurement test and the full RBAC-matrix regression test, both currently
named as real (not hypothetical) gaps rather than glossed over.
