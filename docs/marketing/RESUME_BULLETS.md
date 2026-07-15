# Resume Bullets — SigmaForge

Three ATS-friendly bullets. Each is true today (E0, release-audited) — none
claims research results or detection-engineering features that don't exist
yet. Swap in whichever framing matches the job description's emphasis.

1. Architected and built the authentication and authorization core of an
   AI-security research platform in FastAPI and PostgreSQL, implementing
   RS256 JWT authentication, rotating single-use refresh tokens with
   theft-reuse detection, and declarative RBAC across 5 roles — backed by
   20 automated tests and a repository-pattern design that decouples
   business logic from the database layer.

2. Designed a dual-track engineering and AI-security research architecture
   for detecting adversarial sabotage in LLM-generated Sigma detection
   rules, producing a pre-registered research design (falsifiable
   hypotheses, Wilson score confidence intervals, Holm-Bonferroni
   correction) and a full 20-table PostgreSQL schema supporting both the
   production platform and the experiment pipeline.

3. Established a production-grade CI/CD pipeline (GitHub Actions) covering
   lint, type-checking, automated testing, dependency vulnerability
   scanning, full Docker Compose integration verification, and container
   security scanning (Trivy) across a FastAPI backend, Celery worker, and
   React/TypeScript frontend — plus a documented release audit process
   that caught and fixed 6 real issues before the first public tag.
