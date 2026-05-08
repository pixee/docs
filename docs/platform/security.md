---
title: "Security & Trust"
slug: /platform/security
track: both
content_type: guide
seo_title: "Security & Trust | Pixee AI Safety and Guardrails"
description: How Pixee validates AI-generated fixes, protects your code, and preserves human authority. Fix validation layers, data handling, and deployment models.
sidebar_position: 6
---

Pixee applies multiple independent validation layers before any AI-generated code change reaches a developer. Every fix passes automated quality evaluation, and every fix ships as a pull request — never a direct commit. Your existing code review, CI/CD pipelines, and SAST re-scanning all apply to Pixee changes exactly as they do to human-written code. The measured result: a 76% merge rate on production deployments.

## Trust Framework

Pixee's trust model rests on three governing principles:

**1. Narrow scope.** Pixee fixes SAST-identified security issues — typically 1-5 lines adding input validation, parameterized queries, or safe API calls. It does not write features, generate business logic, or create new functionality.

**2. Defense in depth.** No single validation layer is considered sufficient. Multiple independent checks operate in sequence: constrained generation, independent evaluation, pull request review, CI/CD testing, and SAST re-scanning. If one layer misses something, the next catches it.

**3. Human authority preserved.** Pixee adds validation layers before changes reach your existing review process. Developers always have final approval. There is no mode, setting, or override that bypasses human review.

## Deterministic vs. AI Fixes

This distinction is the most important concept on this page.

| Dimension | Deterministic Codemods | AI-Generated MagicMods |
|---|---|---|
| **Input/output predictability** | Identical output every time | Output varies based on context; constrained by dataflow-bounded input |
| **Scope** | Known vulnerability patterns (SQL injection, XSS, SSRF, deserialization, etc.) | Novel, custom, and multi-file patterns |
| **Hallucination risk** | Zero | Mitigated by independent evaluation and retry/suppression |
| **Validation requirement** | Pre-validated by design; open-source engines inspectable | Mandatory independent evaluation gate |
| **LLM involvement** | None | Constrained generation with per-rule knowledge base guidance |

**Deterministic codemods** handle known vulnerability patterns — SQL injection parameterization, SSRF prevention, insecure deserialization, weak cryptography, and more. These are pre-built, rule-based transformations with zero LLM involvement. The open-source engines (codemodder-java, codemodder-python) are publicly inspectable — your security team or auditors can review the transformation rules before deployment.

**AI-powered MagicMods** fire only when deterministic rules cannot reach — custom framework wrappers, multi-file dataflow vulnerabilities, novel patterns. Every MagicMod fix passes through the full independent evaluation pipeline.

Routing between modes is automatic — no manual configuration.

## Independent Fix Evaluation

Every AI-generated fix passes through an independent quality gate before a developer sees it.

**Separate inference call, not self-critique.** The evaluator runs as a structurally independent inference call — separate context window, separate system prompt, separate scoring rubric — not the same process that generated the fix. This prevents the "grading your own homework" failure mode.

**Three-dimension rubric:**

| Dimension | What It Checks |
|---|---|
| **Safety** | No behavior changes beyond fixing the vulnerability. No breaking API changes, missing imports, or unintended side effects. |
| **Effectiveness** | Correctly addresses the security issue. The SAST scanner should stop flagging this finding after the fix is applied. |
| **Cleanliness** | Proper formatting, indentation, no extraneous changes. Preserves existing comments and code structure. |

**All three dimensions must pass.** This is not an aggregate score that lets a dangerous fix through because it scored well on formatting.

**Structured feedback loop.** Fixes that fail receive specific reasoning. The generator uses this feedback to produce a better fix. If a fix still cannot pass after retries, it is suppressed entirely — with the suppression reasoning logged.

## Your Existing Gates Still Apply

Pixee adds validation before your existing quality controls. It does not replace them.

After Pixee creates a PR:

1. **Code review** by your development team
2. **CI/CD pipeline execution** — tests, builds, and any other automated checks
3. **SAST re-scanning** by the same tools that found the original vulnerability
4. **Branch protection rules** and merge requirements you have configured

Every Pixee change flows through your full approval pipeline. PR-only delivery is an architectural constraint — there is no mode, setting, or override that allows direct branch commits.

## Data Handling

**Input scope limitation.** Only code relevant to the specific vulnerability is sent to AI models — not entire repositories. File paths are relative to project root only. No absolute paths, repository URLs, git metadata, commit hashes, or author information are sent.

**Stateless inference.** Each analysis is isolated. A single analysis cannot modify the model, persist across analyses, or affect other applications.

**Adversarial input protection.** Code analyzed by an LLM is itself a potential attack vector — malicious comments or string literals could attempt prompt injection. Mitigations: input scope limitation (only vulnerability-relevant snippets sent), independent output validation (separate evaluator catches anomalous fixes), narrow generation scope (constrained to OWASP/SANS patterns), and deterministic-first routing (most fixes use zero-LLM codemods).

**Customer-controlled AI deployment.** Pixee uses your own AI deployment — Azure OpenAI, Azure AI Foundry, Anthropic Claude, or any OpenAI-compatible endpoint. Your contractual terms with that provider govern data handling.

## Deployment Models

| Model | What It Provides |
|---|---|
| **Cloud SaaS** | Pixee-managed infrastructure. Pixee accesses repositories via SCM integration (read-only code access, write access limited to PR creation). |
| **Embedded cluster** | Turnkey self-hosted deployment on a single Linux VM. No Kubernetes expertise required. All data stays in your network. |
| **Helm / BYO Kubernetes** | Deploys into your existing Kubernetes infrastructure (EKS, GKE, AKS, or self-managed). |
| **Air-gapped** | Fully disconnected operation with customer-hosted LLM. Zero outbound internet after installation. |

For air-gapped deployments, a customer-hosted LLM is required. The only outbound connection is license validation, which can be proxied.

## Rollback and Reversibility

- **Standard git revert.** Every Pixee change is a normal Git commit within a pull request.
- **Full traceability.** All fixes are stored in Git history with complete context.
- **No lock-in dependency.** If Pixee were removed entirely, all previously merged fixes remain as standard code in the repository.
- **Pre-merge rejection is trivial.** Closing a PR without merging discards the proposed change with zero impact.

## Responsible AI Governance

Pixee is designed for AI governance committee review. Concrete answers to common governance questions:

| Question | Answer |
|---|---|
| **What does the AI generate?** | Security fixes only — 1-5 line changes applying OWASP/SANS patterns. |
| **Who validates the output?** | An independent evaluation layer (separate inference call), then your developers via PR review, then your CI/CD and SAST re-scanning. |
| **Can it bypass human approval?** | No. PR-only delivery is an architectural constraint, not a configuration option. |
| **What data does it access?** | Only code relevant to the specific vulnerability. No entire repositories, no PII, no secrets. |
| **What if it is wrong?** | Fixes that fail quality evaluation are suppressed. Fixes that pass are reviewed by developers. Merged fixes can be reverted with standard Git operations. |
| **What is the deterministic floor?** | Common vulnerability patterns are fixed with zero AI involvement using publicly inspectable, open-source codemod engines. |
| **What controls exist on the AI itself?** | Constrained generation with security-specific context only, independent evaluation, structured retry with feedback, suppression on failure. |

## Audit Defensibility

For regulated industries, every Pixee fix creates a defensible audit record:

- Typed triage verdict (true positive, false positive, won't fix, suspicious) with code-level evidence
- Fix quality scores (Safety, Effectiveness, Cleanliness) on every PR
- Full Git history showing what changed, when, and why
- SAST re-scanning confirmation that the fix does not introduce new findings
- Developer approval recorded in the merge event

Compliance teams reviewing automated code changes need to see that the change was validated by independent evaluation, reviewed by a human, tested by CI/CD, and re-scanned by the same tools that found the original issue. Pixee's pipeline provides all four.
