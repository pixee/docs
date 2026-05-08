---
title: "Security & Trust"
slug: /platform/security
track: leader
content_type: conceptual
seo_title: "Security & Trust | Pixee AI Safety and Guardrails"
description: How Pixee validates AI-generated fixes, protects your code, and preserves human authority. Fix validation layers, data handling, and deployment models.
sidebar_position: 6
---

Pixee applies multiple independent validation layers before any AI-generated code change reaches a developer. Every fix must pass automated quality evaluation, and every fix ships as a pull request -- never a direct commit. Your existing code review, CI/CD pipelines, and SAST re-scanning all apply to Pixee changes exactly as they do to human-written code. The result: defense-in-depth controls that Responsible AI Councils, compliance officers, and engineering leaders can verify. See [Fix Safety](/how-it-works/fix-safety) for merge rate data.

This page details what data Pixee accesses, where it goes, what controls prevent bad output, and how the architecture differs from general-purpose AI coding tools. If you are evaluating whether AI-generated code changes can be trusted in production, this is the page to read most carefully.

## Trust Framework

Pixee's trust model rests on three governing principles:

**1. Narrow scope.** Pixee fixes SAST-identified security issues -- typically 1-5 lines adding input validation, parameterized queries, or safe API calls. It does not write features, generate business logic, or create new functionality.

**2. Defense in depth.** No single validation layer is considered sufficient. Multiple independent checks operate in sequence: constrained generation, independent evaluation, pull request review, CI/CD testing, and SAST re-scanning. If one layer misses something, the next catches it.

**3. Human authority preserved.** Pixee adds validation layers BEFORE changes reach your existing review process. Developers always have final approval. There is no mode, setting, or override that bypasses human review.

These three principles produce the following architecture:

## Fix Quality Validation

Every fix passes through three independent layers before reaching a developer:

### Layer 1: Constrained Generation

The AI receives only security-relevant code context alongside established OWASP/SANS remediation patterns. No customer proprietary information is used in pattern libraries -- only industry-standard security guidance. This constrains the solution space to known-good security patterns rather than open-ended code generation.

For common vulnerability patterns, generation is entirely deterministic. Pre-built codemods apply rule-based transformations with zero LLM involvement. Same input, same output, every time. These fixes carry zero hallucination risk by design.

### Layer 2: Independent Evaluation

A separate inference call -- structurally independent from the generator -- scores every fix on three dimensions:

| Dimension         | What It Checks                                                                                                             |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------- |
| **Safety**        | No behavior changes beyond fixing the vulnerability. No breaking API changes, missing imports, or unintended side effects. |
| **Effectiveness** | Correctly addresses the security issue. The SAST scanner should stop flagging this finding after the fix is applied.       |
| **Cleanliness**   | Proper formatting, indentation, no extraneous changes. Preserves existing comments and code structure.                     |

A fix must pass all three dimensions. This is not an aggregate score that lets a dangerous fix through because it scored well on formatting. See [Fix Safety](/how-it-works/fix-safety) for merge rate data.

The critical design choice: the evaluator runs as a structurally independent inference call -- separate context window, separate system prompt, separate scoring rubric -- not the same process that generated the fix. This independence prevents the generator from grading its own work. For security leaders accustomed to defense-in-depth thinking, this is a familiar pattern -- multiple independent controls, no single point of reliance.

**What happens when a fix fails:** The evaluator produces specific reasoning and suggestions. The generator uses this feedback to produce a better fix. If the fix still cannot pass after retries, it is suppressed entirely -- the developer never sees it, and the suppression reasoning is logged.

### Layer 3: Customer Control Integration

All changes are delivered as pull requests. Your controls then apply:

- Code review by your development team
- CI/CD pipeline execution (tests, builds, linting)
- SAST re-scanning of the proposed fix by the same tools that found the original vulnerability
- Branch protection rules and merge requirements you have configured

Pixee adds validation layers before your existing gates. It does not replace or bypass any of them.

## Hybrid Intelligence Architecture

Pixee does not rely on AI for every fix. The system uses a hybrid model with direct trust implications:

**Deterministic codemods** handle known vulnerability patterns -- SQL injection parameterization, SSRF prevention, insecure deserialization, weak cryptography, and more. These are pre-built, rule-based transformations with zero LLM involvement. Zero hallucination risk. Reproducible output. The open-source engines (codemodder-java, codemodder-python) are publicly inspectable -- your security team or auditors can review the transformation rules before deploying Pixee. See [Fix Generation](/how-it-works/fix-generation) for the full codemod library.

**AI-powered MagicMods** fire only when deterministic rules cannot reach -- custom framework wrappers, multi-file dataflow vulnerabilities, novel patterns. Every MagicMod fix passes through the full independent evaluation pipeline. Deterministic codemods do not need this gate because their output is pre-validated by design. AI fixes earn their way through.

Deterministic codemods carry zero AI risk. AI-generated fixes receive additional validation through the independent evaluation pipeline.

## Triage and Remediation Trust Architecture

Beyond fix validation, the triage and remediation engines each embed trust-specific design choices:

**Triage: beyond reachability.** Many tools stop at checking whether a vulnerable function is reachable. Pixee evaluates dataflow quality, production versus test classification, security control detection, and severity adjustment. Every verdict includes code snippets showing the evidence. Auditors can see exactly why a finding was classified as it was. The three-tier progressive architecture (deterministic, agentic, adaptive) means most findings resolve at Tier 1 with zero LLM cost and reproducible, auditable verdicts. See [Triage Capabilities](/platform/triage) for full details.

**Remediation: multi-agent fix planning.** Complex multi-file fixes are planned before execution by specialized agents handling version decisions, source file identification, and manifest updates independently. Plans are evaluated for quality before code changes begin. The result: atomic PRs with no half-done upgrades. See [Remediation Capabilities](/platform/remediation) for full details.

## Human-in-the-Loop Design

PR-only workflow is a non-negotiable architectural constraint, not an optional configuration:

- **Never direct commits.** No mode, setting, or override allows direct branch commits.
- **Full diff visibility.** Developers see what changed, why, and the quality scores.
- **SAST re-scanning.** The same tools that found the vulnerability scan the fix.
- **Standard Git rollback.** `git revert` applies to any merged change.
- **No lock-in.** Removing Pixee leaves all merged fixes intact. No runtime dependency.

## Data Handling and Privacy

What data Pixee accesses, and what it does not:

**Input scope limitation.** Only code relevant to the specific vulnerability is sent to AI models -- not entire repositories. File paths are relative to project root only. No absolute paths, repository URLs, git metadata, commit hashes, or author information are sent.

**Adversarial input protection.** Code analyzed by an LLM is itself a potential attack vector -- malicious comments or string literals could attempt prompt injection. Pixee mitigates this through input scope limitation (only vulnerability-relevant snippets sent), independent output validation (separate evaluator catches anomalous fixes), narrow generation scope (constrained to OWASP/SANS patterns), and deterministic-first routing (most fixes use zero-LLM codemods). For the full treatment of adversarial input defense, see [Security Architecture -- Adversarial Input Protection](/enterprise/security-architecture#adversarial-input-protection).

**Stateless inference.** Each analysis is isolated. A single analysis cannot modify the model, persist across analyses, or affect other applications.

**Customer-controlled AI deployment.** Pixee uses your own AI deployment -- Azure OpenAI, Azure AI Foundry, Anthropic Claude, or any OpenAI-compatible endpoint. Your contractual terms with that provider govern data handling.

**On-premises deployment.** Pixee deploys entirely on-premises when required. No code leaves your environment. Three deployment models:

| Model                     | What It Provides                                                                                   |
| ------------------------- | -------------------------------------------------------------------------------------------------- |
| **Embedded cluster**      | Turnkey self-hosted deployment with all infrastructure included. No Kubernetes expertise required. |
| **Helm / BYO Kubernetes** | Deploys into your existing Kubernetes infrastructure (EKS, GKE, AKS, or self-managed).             |
| **Air-gapped**            | Fully disconnected operation with customer-hosted LLM. Zero outbound internet after installation.  |

## Enterprise Security Concerns Addressed

Common questions about AI-generated code changes, answered with architectural details.

### "AI-generated code is too risky for production."

Most common patterns use deterministic codemods with zero AI involvement. AI-generated fixes pass an independent evaluation gate before a developer sees them. The PR workflow ensures nothing reaches production without human approval. The same SAST tools that found the issue scan the fix.

### "We cannot send proprietary code to an LLM."

Pixee sends relevant code snippets -- not entire repositories -- to your own AI deployment. Azure OpenAI and equivalent providers guarantee customer data is not used for model training. For on-premises deployments, code never leaves your infrastructure. The only outbound connection is license validation, which can be proxied.

### "What types of changes does the AI make?"

Pixee fixes SAST-identified security vulnerabilities (1-5 lines, OWASP/SANS patterns). Deterministic codemods handle known patterns with zero AI involvement. AI-generated fixes pass an independent evaluation layer before reaching a PR. Fixes that fail quality evaluation are suppressed.

### "What about data residency?"

Pixee deploys on-premises or in your cloud. AI inference uses your deployment in your region. Only outbound connection: license validation (can be proxied). Air-gapped deployments require zero outbound internet after installation.

### "Our Responsible AI Council needs to review this."

Pixee is designed for exactly this scrutiny. The architecture provides concrete answers to every question a governance committee asks:

- **What does the AI generate?** Security fixes only -- 1-5 line changes applying OWASP/SANS patterns.
- **Who validates the output?** An independent evaluation layer (separate inference call), then your developers via PR review, then your CI/CD and SAST re-scanning.
- **Can it bypass human approval?** No. PR-only delivery is an architectural constraint, not a configuration option.
- **What data does it access?** Only code relevant to the specific vulnerability. No entire repositories, no PII, no secrets.
- **What if it is wrong?** Fixes that fail quality evaluation are suppressed. Fixes that pass are reviewed by developers. Merged fixes can be reverted with standard Git operations.
- **What is the deterministic floor?** Common vulnerability patterns are fixed with zero AI involvement using publicly inspectable, open-source codemod engines. See [Fix Generation](/how-it-works/fix-generation) for the codemod library.
- **What controls exist on the AI itself?** Constrained generation with security-specific context only, independent evaluation, structured retry with feedback, suppression on failure.

## Frequently Asked Questions

### Is automated vulnerability remediation safe for production code?

Every fix passes independent quality evaluation (Safety, Effectiveness, Cleanliness) before reaching a PR. Most common patterns use deterministic codemods with zero AI involvement. Your existing code review, CI/CD, and SAST re-scanning all apply. See [Fix Safety](/how-it-works/fix-safety) for merge rate data.

### What happens if an automated fix introduces a bug?

Standard `git revert` applies -- every Pixee change is a normal Git commit within a PR. Fixes are typically 1-5 lines. There is no runtime dependency on Pixee for merged code.

### How does Pixee handle my proprietary code?

Pixee sends only vulnerability-relevant code to AI models, not entire repositories. On-premises deployment keeps all code within your environment. File paths are relative to project root only -- no absolute paths, repository URLs, git metadata, or author information.

### How accurate are AI-generated security fixes?

Many fixes use deterministic codemods with zero AI variance. AI-generated fixes pass an independent evaluation gate structurally separate from the generator. Fixes that cannot pass are suppressed, not shipped. See [Fix Safety](/how-it-works/fix-safety) for merge rate data.
