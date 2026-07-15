# Future Work — Auth Subsystem

Genuine deferred scope, cross-referenced with `ROADMAP.md`. Nothing here is
implemented today; each item states why it isn't yet and, where known,
which milestone is expected to pick it up.

| Item | Why deferred | Target |
|---|---|---|
| Timing-side-channel measurement test | Requires statistical measurement infrastructure (repeated timed requests, distribution comparison) beyond E0's functional-test scope. The mitigation exists in code; the proof it works does not yet. | E5 Hardening |
| Full RBAC-matrix regression test (every role × every permission) | E0 has 5 roles and a handful of permissions; a table-driven test asserting `ROLE_PERMISSIONS` matches `API_SPECIFICATION.md` §14 cell-by-cell is straightforward but wasn't written this milestone. Real gap, not a design decision. | Before E1 lands more permissions |
| Multi-factor authentication | Out of scope for an internal-tool MVP; no threat-model finding currently rates it as blocking for E0's user base (small internal security team). | Unscheduled — revisit if externally exposed |
| Password reset / email verification | Requires an email-sending subsystem that doesn't exist yet. | Unscheduled |
| Session/device management UI | `logout_all()` exists (revoke everything); revoking one named session by device requires frontend + endpoint work not yet scoped. | Unscheduled |
| SSO / OAuth federation | No current requirement from `PRD.md`; would be additive to, not a replacement for, the existing login flow. | Unscheduled |
| Access-token denylist for instant revocation | Deliberately deferred — see `DESIGN_DECISIONS.md` for the reasoning (short TTL + per-request `is_active` check as the interim mitigation). | Revisit only if a real incident demonstrates the 15-minute window is unacceptable |
| Rate limiting at the network/IP level | Account lockout protects a single account; nothing yet throttles distributed credential-stuffing across many accounts from one source. | E5 Hardening (already scoped there in `ROADMAP.md`) |
| `researcher` role real usage | Permissions are seeded and RBAC-tested now, but nothing in the product currently authenticates as `researcher` — that begins with the research track. | R0 onward |
