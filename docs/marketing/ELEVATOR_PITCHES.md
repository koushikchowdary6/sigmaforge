# Elevator Pitches — SigmaForge

All honest to current scope (v0.1.0 / E0): the platform foundation is
built and tested; detection-engineering features and the research study
itself are designed but not yet built.

---

## For a startup CTO

### 30 seconds
"SigmaForge is a detection-engineering platform with a research angle:
it's built to measure whether LLM-assisted rule generation can be
adversarially manipulated to produce rules with hidden blind spots. Right
now I've shipped the foundation — real auth, RBAC, full CI/CD, a schema
that supports both the product and the research pipeline — and I'm about
to start on the actual rule-authoring engine. I designed it so the
research instrument and the production tool are the same code path, not
two separate builds."

### 2 minutes
"Most AI-assisted security tooling optimizes for 'does the LLM write a
good rule.' I got interested in the adjacent question: if an attacker
controls part of what the LLM sees — a poisoned threat report, a
misleading FP comment — can they get it to write a rule that looks fine
to a reviewer but has a specific gap? That's a supply-chain question for
AI-assisted engineering, not just a model-quality question.

I structured the project so the production detection-engineering platform
and the research experiment share one codebase — the same rule-approval
workflow that a real SOC team would use is also the instrument that
measures human catch rate in the study, verbatim, not a simulation of it.
That was a deliberate architecture decision because I didn't want the
research result to depend on artificial lab conditions.

Right now what's built and tested is the foundation: authentication with
RS256 JWT and rotating refresh tokens, role-based access control across
five roles, the full 20-table schema, a Celery worker, a React frontend,
and a CI pipeline that boots the whole Docker Compose stack on every PR. I
just finished a release audit — found and fixed six real issues before
tagging v0.1.0, documented all of it. Next up is the actual rule-authoring
and validation engine, which is also the load-bearing piece the research
track depends on."

### What a CTO probably wants to know next
Whether this generalizes beyond Sigma/detection engineering (the
architecture pattern — shared production/research code path — does), and
what the realistic timeline is (4-5 months part-time for the full
dual-track plan, stated plainly in the roadmap rather than compressed for
effect).

---

## For a Security Engineering Manager

### 30 seconds
"It's a Sigma detection-rule platform — author, validate, map to MITRE
ATT&CK, approve, deploy — with AI assistance built in as a sidecar, not a
dependency; every core workflow has to work with AI disabled. I've built
and tested the auth/RBAC foundation and the full schema; the rule-authoring
engine is next."

### 2 minutes
"The core idea is a governed workflow for detection rules: draft, validate
against real telemetry samples, map to ATT&CK, route through peer
approval with mandatory review comments and self-approval prevention,
deploy to Splunk or Elastic, track false-positive rate and coverage over
time. AI can draft or refine a rule and summarize an alert, but it's
architecturally isolated — every core workflow has to function with the AI
service fully disabled, which was a deliberate constraint from the PRD, not
an afterthought.

What's actually built right now is the foundation: real authentication
(RS256 JWT, rotating refresh tokens with theft-reuse detection — presenting
an already-used token burns every session for that user), role-based
access control across five roles enforced through one declarative
permission check rather than scattered role-name comparisons, and the full
production database schema. 20 automated tests are passing. I also ran a
release audit before publishing — the kind of thing I'd want a team to do
before every release, not just the first one — and it caught real issues:
an unused dependency, a missing test-infrastructure lockfile, a Docker
Compose service with an unnecessary dependency that would've slowed
startup for no reason.

The detection rule authoring and validation engine — the part your team
would actually touch day to day — is the next milestone."

### What a manager probably wants to know next
How the approval workflow prevents a single compromised or careless
reviewer from rubber-stamping a bad rule (self-approval prevention plus
mandatory comments plus full audit logging on every mutating action, per
`docs/THREAT_MODEL.md` — not yet built, but designed), and how false
positives get tracked back to a rule's owner over time (the schema
supports it now; the workflow is E2).

---

## For an Anthropic AI Security Fellowship reviewer

### 30 seconds
"I'm building an adversarial evaluation of whether LLM-generated Sigma
detection rules can be subtly sabotaged by manipulated context — a
sabotage-evaluation study in the spirit of Anthropic's own work, applied
to a security-tooling domain I don't think has been covered yet. The
research design is pre-registered with falsifiable hypotheses, and I
already caught and fixed a real ground-truth circularity bug in my own
draft before writing any experiment code. Right now I've built the
production platform foundation the study depends on; the experiment
pipeline itself hasn't run yet."

### 2 minutes
"The gap I'm targeting: Sublime Security, CTI-REALM, and GenTI all measure
LLM-generated detection rule quality under cooperative conditions. None of
them ask what happens when the input context is adversarial — when an
attacker can shape the threat-intel report or false-positive comment an
LLM sees while drafting a rule. That's a sabotage-evaluation question, and
it hasn't been asked in this specific domain as far as I could find in one
search pass — which I flag as a real limitation of my lit review, not a
confident claim of novelty.

The research design commits up front to four falsifiable hypotheses,
Wilson score confidence intervals, Holm-Bonferroni correction for multiple
comparisons across a corpus of roughly 60-80 attack scenarios spanning at
least 15 ATT&CK techniques, and explicit failure-mode criteria that are
distinct from a hypothesis being falsified — an underpowered sample isn't
the same finding as a null result, and I don't want to conflate them under
pressure to report something.

The methodological problem I'm proudest of catching myself: my first draft
scored the automated differential verifier — which establishes ground
truth for whether a rule is actually sabotaged — as a peer 'defense'
alongside human review. That's circular. I caught it before building
anything and rewrote the metrics section to separate the ground-truth role
from the defense-under-test role cleanly.

What exists today is the production platform this depends on: the same
rule-approval workflow a real user would go through is what the
human-review study measures catch rate against later, not a separate lab
harness. What doesn't exist yet is the experiment pipeline itself — I
haven't generated a single adversarial rule or run a single trial. I'd
rather say that plainly than imply results I don't have."

### What a fellowship reviewer probably wants to know next
Whether the "no existing paper answers this" claim holds up under a more
systematic literature search (I've flagged this as an open risk in
`docs/RELATED_WORK.md` myself), and what the plan is if the headline result
turns out to be null or weak (`docs/ROADMAP.md`'s R4 milestone commits to
reporting that honestly if it happens, rather than only publishing a
positive result).
