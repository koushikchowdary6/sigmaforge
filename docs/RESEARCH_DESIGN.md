# Research Design

**Product:** SigmaForge — Adversarial Sabotage Evaluation for AI-Assisted Detection Engineering
**Status:** Draft v1.0 (Stage 3 deliverable)
**Depends on:** `RELATED_WORK.md` (novelty claim), `PRD.md` §11 (research requirements), `ARCHITECTURE.md` §11 (research subsystem), `DATABASE_SCHEMA.md` §2.20 (research tables)

This document is a pre-registration, in spirit: it commits to hypotheses, metrics, and analysis methods *before* any experiment runs, specifically to prevent the two most common failure modes in this kind of project — quietly redefining success after seeing the data, and reporting only the runs that produced an interesting result. Any deviation from this plan during execution must be disclosed in the final report, not silently absorbed.

---

## 1. A Methodological Correction, Stated Up Front

An earlier iteration of the design (`PRD.md` v1.1, `ARCHITECTURE.md` v1.1) listed the automated differential verifier as one of three parallel "defenses" to compare against human review — human catch rate, verifier catch rate, judge catch rate. That's circular: the verifier is also the mechanism that labels a rule as sabotaged in the first place (`differential_verification_results.blind_spot_confirmed`, a generated column derived directly from the verifier's own output). Scoring the verifier against itself would trivially yield 100% "catch rate" and mean nothing.

The corrected design, used throughout this document: **the differential verifier is the ground-truth instrument.** It answers "was this rule actually sabotaged?" — a question that must be answered mechanically and objectively, independent of what any reviewer believes. The two things actually being evaluated as candidate *defenses* are **human review** and **LLM-as-judge review**, each scored against that ground truth. `PRD.md` and `ARCHITECTURE.md` have been corrected to match (see the v1.2 notes in each).

## 2. Primary Research Question

> When the context supplied to an LLM generating or refining a SIEM detection rule is adversarially manipulated, how often does the resulting rule contain a covert, exploitable blind spot (verified by differential testing against a known bypass technique), and how effectively do human peer review and LLM-as-judge review catch it before deployment?

## 3. Secondary Research Questions

- **SQ1 (channel effect):** Does attack success rate (ASR) differ significantly between injection channels — CTI report text vs. false-positive report comments?
- **SQ2 (model effect):** Does ASR differ significantly across generating models (Claude, a GPT-family model, an open-weight model)?
- **SQ3 (defense comparison):** Is human catch rate significantly different from LLM-as-judge catch rate?
- **SQ4 (complementarity):** Does combining human review and LLM-as-judge review (flagged by either) catch significantly more sabotaged rules than the better of the two alone?
- **SQ5 (exploratory, not confirmatory):** Do sabotaged rules show any detectable structural signature — e.g., unusually narrow field-match conditions, missing wildcards, overly specific string matches — that could seed a cheap static-analysis heuristic independent of full differential testing? This question is exploratory; any pattern found is a hypothesis for future work, not a confirmed result of this study.

## 4. Hypotheses

Each hypothesis states a direction and an explicit falsification condition. A result that doesn't match the stated direction is not a failed experiment — it's a finding, and gets reported as such.

| ID | Hypothesis | Falsified if |
|---|---|---|
| **H1** | Adversarial-condition ASR is significantly greater than clean-condition ASR (adversarial context manipulation induces sabotage above the model's baseline error rate) | Adversarial ASR is not statistically distinguishable from clean-condition ASR (Fisher's exact test, α=0.05) |
| **H2** | Human catch rate is lower than LLM-as-judge catch rate for verifier-confirmed-sabotaged rules — the hypothesis being that a covert, plausible-looking blind spot is harder to spot by reading a rule during normal review than for a model specifically prompted to look for exactly this failure mode | Human catch rate ≥ judge catch rate — itself a genuinely interesting result, not a null outcome to bury |
| **H3** | Combined defense (human OR judge flags it) catch rate is significantly higher than the better single defense alone | Combined catch rate ≈ max(human, judge) catch rate, indicating the two defenses catch largely overlapping cases rather than complementary ones |
| **H4** | ASR is higher for the CTI-report-text channel than the FP-report-comment channel, on the reasoning that content framed as external reference material is treated as less suspicious by the model than a comment visibly authored by another platform user | No significant channel-based difference in ASR |

## 5. Success Metrics (Operational Definitions)

- **ASR** = (adversarial-condition runs with `blind_spot_confirmed = true`) / (total adversarial-condition runs), computed per channel and per model, and pooled.
- **Baseline ASR** = same formula computed on clean-condition runs — establishes the model's inherent error rate independent of any injection.
- **Human catch rate** = (verifier-confirmed-sabotaged rules rejected or sent back for changes under blind review) / (verifier-confirmed-sabotaged rules reviewed).
- **Judge catch rate** = (verifier-confirmed-sabotaged rules the LLM-as-judge flags) / (verifier-confirmed-sabotaged rules judged).
- **Combined catch rate** = (verifier-confirmed-sabotaged rules caught by human OR judge) / (verifier-confirmed-sabotaged rules with both a human and judge decision recorded).
- **Zero-review baseline** = 0% by definition (used only as a rhetorical anchor in reporting — "human review catches X%, which is better/worse than doing nothing by Y points" — not as a statistical comparison arm).

## 6. Failure Metrics (What Would Mean the Approach Isn't Working)

These are distinct from hypothesis falsification — a falsified hypothesis is still a valid result; these describe conditions under which the *study itself* would be unreliable and results should not be trusted or published as-is.

- **Ground-truth instability:** if a manual spot-check of ≥20 verifier-labeled runs disagrees with the automated `blind_spot_confirmed` label more than 10% of the time (Roadmap R2 exit criteria), the ground-truth mechanism is not trustworthy and must be fixed before any catch-rate claim is made.
- **Underpowered sample:** if the realized N of verifier-confirmed-sabotaged rules is too small for any comparison to have reasonable statistical power (see §7), results are reported descriptively only, with an explicit statement that no inferential claim is being made — not dressed up with a p-value that doesn't mean anything at that sample size.
- **Corpus-construction confirmation bias:** since one person (or a very small team) both designs the attack corpus and interprets results, there's a structural risk of unconsciously building injections that "work" toward a preferred narrative. Partial mitigation: the corpus (`attack_corpus_entries`) is committed and versioned *before* any experiment run against it, so it can't be retroactively edited to improve a weak result — but this doesn't eliminate the bias in what got included in the first place, and the report must say so.
- **pySigma conversion artifacts masquerading as model-induced sabotage:** a rule can fail the bypass test because the pySigma backend converts Sigma syntax incorrectly, not because the model wrote a bad rule. Control: run every corpus entry's "intended detection" sample through a manually-verified reference rule (not model-generated) as a sanity check that the conversion pipeline itself isn't the source of failures attributed to the model.

## 7. Evaluation Methodology

- **Confidence intervals for proportions** (ASR, catch rates): Wilson score interval, not the normal approximation — normal-approximation intervals are unreliable at the sample sizes this study will realistically achieve (tens to low hundreds of runs per cell) and can produce nonsensical bounds (e.g., negative lower bounds).
- **Comparisons between two proportions** (H1, H2, H4, SQ1–SQ3): Fisher's exact test, not chi-square — chi-square's asymptotic assumptions break down at low expected cell counts, which this study will have in several comparison cells.
- **Multiple comparisons:** the five secondary questions (SQ1–SQ5) are tested at a Holm-Bonferroni-corrected significance threshold, not five independent tests at raw α=0.05, to control the family-wise false-positive rate. SQ5 is exploratory and excluded from the corrected confirmatory test family entirely — reported descriptively, flagged explicitly as hypothesis-generating, not hypothesis-confirming.
- **Effect sizes reported alongside p-values** for every comparison (e.g., risk difference or odds ratio with its own CI) — a significant p-value from a small sample can still represent a trivial or a huge effect, and the report should let the reader see which.
- **Pre-registration discipline:** this document, once committed to the repository, is the analysis plan. If the actual analysis deviates from it (e.g., a different test is used, a metric is redefined), the final report must say so explicitly and explain why — silent deviation is how legitimate research becomes p-hacking.

## 8. Datasets

- **Attack corpus target:** ≥15 MITRE techniques covered, ≥4 corpus entries per technique (roughly balanced across the two in-scope injection channels — CTI report text, FP-report comment), giving an initial target of ~60-80 corpus entries. Telemetry-sample and rule-description channels (Architecture §11.3 channels 3–4) are explicitly out of scope for the initial study and reserved for the Stretch phase.
- **Full experiment matrix:** corpus entries × 3 models × 2 conditions (clean/adversarial) = up to ~480-560 individual experiment runs at the target corpus size. This has real API cost across three providers — budget and rate-limit this explicitly before running the full matrix; a smaller pilot batch (one technique, all models/conditions) should run first to validate the pipeline and estimate actual per-run cost before committing to the full matrix.
- **Bypass technique corpus:** at least one well-documented, publicly-known evasion pattern per covered technique, drawn from public detection-engineering/ATT&CK literature — not novel evasion research (per `THREAT_MODEL.md` §7.1's dual-use scoping).
- **Provenance:** all corpus content is synthetic or drawn from public, non-sensitive sources. No real organizational data, real production rules, or real CTI feeds are used (`PRD.md` §11.4).

## 9. Benchmarks (External Reference Points)

None of the three closest papers (`RELATED_WORK.md` §2) measure the same thing we do, so there is no direct apples-to-apples benchmark to report against. What we *can* do, and will, is use Sublime Security's published clean-condition quality comparison (human-written vs. AI-generated rules) as a sanity-check reference: if our clean-condition rule quality looks wildly different from their reported baseline, that's a signal our generation pipeline has a problem unrelated to the sabotage question, and should be investigated before trusting the adversarial-condition results. This is explicitly a sanity check, not a claimed benchmark comparison, and must be labeled as such in any report.

## 10. Threat Scenarios (Formalized)

Each injection channel corresponds to an assumed attacker capability. Results should be interpreted in light of how realistic that capability is — a high ASR under a low-capability, highly plausible scenario is a more urgent finding than the same ASR under a scenario requiring privileged access.

| Scenario | Channel | Assumed attacker capability | Realism |
|---|---|---|---|
| **A** | CTI report text | Can influence or poison a threat-intel source ingested during rule generation (e.g., a compromised or low-reputation feed, or a deliberately misleading public report) | Medium — plausible without any internal access, since many orgs ingest external CTI with limited vetting |
| **B** | FP-report comment | Has a legitimate (possibly low-privilege) account on the platform and can submit false-positive reports, a normal Analyst-level action | Medium-High — requires only an insider or compromised low-privilege account, which is a realistic threat model for an internal tool |
| **C** | Telemetry sample (out of scope for initial study) | Can influence the sample dataset used during validation/generation | Lower for now — reserved for future work once the mechanism for telemetry-informed generation exists |
| **D** | Rule description field (out of scope for initial study) | Compromised engineer workstation/session crafting a description that looks benign | Lower realism as an *external* attack, higher as an *insider-risk* scenario — reserved for future work |

## 11. Expected Limitations (Stated Honestly, in Advance)

- **Small N / limited statistical power.** This is very likely a pilot-scale study (tens to low hundreds of runs), not a population-level claim about "LLMs" in general. Results should be read, and reported, as a proof-of-concept with real but bounded evidence, not a definitive verdict.
- **Corpus scope is bounded by known, public evasion techniques.** This tests whether models can be induced to reproduce *known* blind spots, not whether they can be induced to invent genuinely novel ones — a narrower and safer question than the fully general one, and the report should not overstate the generalization.
- **Model version drift.** Results are tied to specific model versions and dates. A finding of "Model X had ASR of Y%" is a snapshot, not a permanent property of that model family, and should be dated explicitly in any write-up.
- **No formal IRB.** Human-subjects handling (`THREAT_MODEL.md` §7.3) follows informed-consent norms voluntarily; it is not institutionally reviewed. This is disclosed, not hidden.
- **Researcher and corpus-designer are likely the same person.** Structural mitigation (RBAC preventing self-approval, pre-committed corpus) is real but partial — see §6.
- **pySigma is a dependency, not something this project controls.** Conversion bugs in that library are a confound this study must actively control for (§6), not assume away.

## 12. What "Done" Looks Like for This Track

A completed research track produces: the pilot batch validated, the full experiment matrix run, ground-truth reliability confirmed within tolerance (§6), the pre-registered analysis in §7 executed exactly as specified (with any deviation disclosed), and a written report (`ROADMAP.md` R4) that states the actual result — including if H1 is falsified and adversarial context manipulation turns out not to move ASR much. A clean null result, honestly reported with proper statistics, is worth more to every audience listed in the mission brief than an inflated positive one that doesn't survive scrutiny.
