# Engineering Decisions

This note summarizes several design choices in SigmaForge that are easy to miss when reading individual files. It is intentionally about tradeoffs rather than a list of technologies.

## One platform, two purposes

SigmaForge has a production detection-engineering track and a research track studying adversarial manipulation of AI-assisted rule generation. The research harness reuses the production validation and approval paths rather than maintaining a second simplified implementation.

**Why:** the experiment is only meaningful if generated rules are evaluated by the same machinery a real engineer would use. A toy verifier would make the research easier to build but weaken the result.

**Cost:** engineering milestones become hard dependencies for research milestones. The roadmap makes those dependencies explicit rather than pretending both tracks can advance independently.

## Authentication before feature breadth

The foundation milestone implements login, refresh-token rotation, reuse detection, logout/logout-all, and role-based authorization before rule authoring or AI features.

**Why:** detection content, integrations, experiment data, and future model credentials cross different trust boundaries. Retrofitting authorization after feature development would make ownership and audit semantics harder to reason about.

## Async worker boundary

Celery + Redis establish a worker boundary even while the earliest milestone has only a minimal task.

**Why:** rule validation, SIEM deployment, AI generation, corpus experiments, and report generation are naturally asynchronous. Establishing the execution boundary early prevents long-running work from being coupled to HTTP request lifetimes.

**Tradeoff:** this adds infrastructure before there is much background work. The worker therefore has explicit tests proving task execution instead of existing as unused scaffolding.

## Relational database as the source of truth

PostgreSQL stores users, authorization data, rule versions, workflow state, audit records, and experiment metadata. Redis is coordination infrastructure, not the durable record.

**Why:** the important objects have relationships and audit requirements. Versioned rules and experiment provenance benefit from constraints and transactional updates more than from a schemaless store.

## Differential verification for sabotage research

The planned verifier evaluates a generated detection rule against both an intended-detection sample and a matched bypass sample.

**Why:** judging a rule by syntax or an LLM review alone does not establish whether the detection behavior was actually weakened. Behavioral comparison provides a mechanical label that downstream human-review and LLM-as-judge measurements can be scored against.

**Risk:** a verifier can become a single point of methodological failure. The roadmap therefore requires manual spot checks before treating its labels as ground truth.

## Separate production AI and research AI paths

Production AI assistance and adversarial research generation are designed as separate code paths.

**Why:** research prompts and attack corpus content are deliberately hostile. Allowing accidental crossover into normal product flows would create an avoidable trust-boundary failure.

## CI as evidence, not decoration

The repository uses tests, linting, type checking, dependency auditing, frontend builds, and container integration checks as evidence for claims in the README.

The rule for documentation is simple: describe functionality in the present tense only when the repository can demonstrate it. Planned capabilities belong in the roadmap, not in the feature list.

## What I would challenge in a design review

The highest-risk future decisions are not framework choices. They are:

1. how untrusted Sigma/sample content is sandboxed during validation;
2. how SIEM credentials are encrypted and scoped;
3. whether the differential verifier remains valid across multiple backends;
4. how experiment provenance prevents contamination between conditions;
5. whether the human-review study is sufficiently blinded and large enough to support its conclusions.

Those are the areas where additional implementation should be accompanied by tests, threat-model updates, and explicit evidence.