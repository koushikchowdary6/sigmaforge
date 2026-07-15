# LinkedIn Announcement Draft

Posting this as the first public release, not a "finished project" —
the copy below is honest about that on purpose.

---

I just published the first release of SigmaForge, an open-source project I've been building to explore a question I haven't seen answered cleanly yet: can an LLM's detection-engineering output be adversarially sabotaged in ways that pass a normal review process?

Most detection-engineering platforms treat AI-assisted rule generation as a productivity feature. SigmaForge treats it as a security question too. If an attacker can shape the context an LLM sees while it drafts a Sigma rule — a poisoned threat-intel report, a misleading false-positive comment — can they get it to quietly write a rule with a blind spot, one that looks correct to a human reviewer? That's the research question the project is built around, and I designed the study before writing a line of application code: pre-registered hypotheses, a differential verifier for ground truth, a human-review study, and an LLM-as-judge comparison, with explicit falsification criteria so I can't quietly redefine success after seeing results.

This first release (v0.1.0, milestone "E0") is the foundation that research depends on: real authentication and RBAC (RS256 JWT, rotating refresh tokens with theft-reuse detection, 5-role access control), a 20-table PostgreSQL schema, a Celery worker, a React/TypeScript frontend, and a full CI/CD pipeline — lint, type-checking, tests, dependency scanning, a full Docker Compose integration boot, and container security scanning on every PR. 20 automated tests are passing, and I ran a release audit before tagging this that found and fixed 6 real issues (an unused dependency here, a missing lockfile there — the kind of thing that's easy to miss and worth catching before anyone else looks at the code).

What's not built yet, said plainly: the actual detection-rule authoring and validation engine, the SIEM integrations, and the research subsystem itself. The architecture and database schema for all of it exist and are documented, but "designed" and "built" are different claims, and I'm trying hard not to blur them — every doc in the repo that describes the full target platform now says explicitly what's real today versus what's planned.

If you work in detection engineering, SOC operations, or AI security research, I'd genuinely value a second set of eyes on the research design — particularly anyone who's thought about ground-truth circularity in adversarial ML evaluations, since that's the trickiest methodological problem I had to work through before I trusted the metric.

Repo, docs, and the full release audit trail are public. Link in comments.

#DetectionEngineering #AISecurity #CyberSecurity #OpenSource #ThreatDetection #MITREATTACK #SecurityEngineering

---

*(~370 words — trim the middle paragraph if a platform enforces a hard limit.)*
