# Security Policy

## Reporting a Vulnerability

This is currently a personal portfolio/research project, not a production service handling real user data. If you find a security issue, please open a GitHub issue tagged `type:security` describing the problem. Do not include working exploit payloads against any hypothetical production deployment in a public issue — describe the class of vulnerability and its location, and a maintainer will follow up privately if more detail is needed.

## Scope

- In scope: the application code in `backend/`, `worker/`, `frontend/`, and the infrastructure config in `infra/`.
- Out of scope: the research subsystem's attack corpus (`docs/RESEARCH_DESIGN.md`, once implemented) is *intentionally* designed to induce failures in an AI-assisted rule-generation pipeline under controlled conditions. Findings there are research results, not vulnerabilities in this repository, unless they reveal a flaw in SigmaForge's own governance controls (e.g., a way to bypass the self-approval prevention documented in `docs/THREAT_MODEL.md` §4.2).

## Supported Versions

Pre-1.0: only the latest commit on `main` is supported. No backported security fixes to older commits until a `v1.0` tag exists.

## Design-Level Security Documentation

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full STRIDE analysis, OWASP Top 10 mapping, and the dual-use/responsible-disclosure policy governing the research subsystem specifically.
