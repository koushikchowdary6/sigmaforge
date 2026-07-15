# Why the Auth Subsystem Exists

SigmaForge is a detection-engineering platform: it stores an org's detection
logic, its approval history, and (starting in the research track) adversarial
experiment data. All of that is only as trustworthy as the identity and
authorization layer sitting in front of it. Two requirements follow directly
from `PRD.md` and `THREAT_MODEL.md`:

1. **Every mutating action must be attributable to a real, authenticated
   user.** Detection rules go through peer approval (`E2`); audit logs
   (`audit_logs` table) need a real `user_id` on every row, not a shared
   service account. This is a compliance and forensic requirement as much as
   a security one — if a sabotaged rule slips into production, the org needs
   to know who approved it and when.

2. **Not every authenticated user should be able to do everything.**
   `API_SPECIFICATION.md` §14 defines five roles (`admin`,
   `detection_lead`, `detection_engineer`, `analyst`, `researcher`) with
   deliberately different permission sets — most pointedly, `researcher`
   can generate and run experiments but cannot approve or deploy rules,
   even experiment-generated ones. That restriction only means something if
   it's enforced in code, not just written in a doc.

The auth subsystem is what makes both of those true. It is intentionally
the first subsystem built (`ROADMAP.md` E0) because nothing else in the
platform can be built or tested honestly without it — every other
subsystem's endpoints are gated by `require_permission()`, and every other
subsystem's tests need a way to simulate "logged in as role X" without
standing up a full Postgres instance.

## What "done" means here, and what it doesn't

E0's exit criterion (`ROADMAP.md`) is narrow on purpose: "seeded admin can
log in, hit `/auth/me`, CI passes on a clean PR." This subsystem does not
yet include password reset, email verification, MFA, session listing/
management UI, or SSO — those are explicitly out of scope for E0 and tracked
in `FUTURE_WORK.md`. Building them now, before any other subsystem exists to
protect, would be effort spent on breadth instead of on the one thing E0
actually needs: a login/refresh/RBAC core that every later milestone can
depend on without being re-litigated.
