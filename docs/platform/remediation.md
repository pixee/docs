---
title: Remediation Capabilities
slug: /platform/remediation
track: leader
content_type: conceptual
seo_title: "Automated Vulnerability Remediation | 76% Merge Rate"
description: How Pixee generates security fixes using deterministic codemods and AI-powered generation with independent quality evaluation.
sidebar_position: 4
---

Pixee generates validated security fixes and delivers them as pull requests. The hybrid-intelligence engine routes each vulnerability to the best fix method: deterministic codemods handle known patterns with zero AI variance, while AI-powered MagicMods handle novel and complex scenarios. Every fix passes independent quality evaluation before reaching a developer, and every change ships as a standard PR through your existing code review workflow. See [Fix Safety](/how-it-works/fix-safety) for merge rate data and [Fix Generation](/how-it-works/fix-generation) for the full codemod library.

Remediation is co-equal with [triage](/platform/triage).

## Hybrid Intelligence Model

Pixee uses two fundamentally different fix engines, routed automatically based on the vulnerability type:

| Engine                     | How It Works                                                                                 | When It Fires                                                                                                                                       | Risk Profile                                                    |
| -------------------------- | -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| **Deterministic codemods** | Pre-built, rule-based code transformations applying OWASP/SANS patterns                      | Known patterns: SQL injection parameterization, SSRF prevention, insecure deserialization, weak cryptography, insecure temp files, SSL/TLS upgrades | Zero hallucination risk. Same input, same output, every time.   |
| **AI-powered MagicMods**   | Constrained AI generation with dataflow-bounded context and per-rule knowledge base guidance | Custom frameworks, multi-file dataflow vulnerabilities, novel patterns, context-dependent sanitization                                              | AI-generated, but independently evaluated before reaching a PR. |

**Routing is automatic.** The system checks whether a deterministic codemod exists for the vulnerability type. If yes, the codemod fires -- sub-second, zero LLM cost. If no deterministic rule can handle it, a MagicMod generates a fix using scanner-aware context. No manual configuration.

**Open-source engines.** The deterministic codemod engines (codemodder-java with 51 core codemods, codemodder-python with 60+ core codemods) are publicly inspectable. Customers and auditors can read the transformation rules before trusting them.

**Scanner-aware dispatchers.** MagicMod includes scanner-aware dispatchers for each natively integrated scanner. Each dispatcher understands the scanner's output format and rule semantics, so the AI receives the right context for each finding.

Known vulnerability patterns use deterministic codemods. AI-powered generation handles custom framework wrappers, multi-file dataflow vulnerabilities, and context-dependent patterns that require understanding the specific codebase.

## Fix Quality Validation

Every generated fix passes through an independent quality evaluation before a developer ever sees it. Bad fixes are rejected, not shipped.

**Three-dimension rubric:**

| Dimension         | What It Evaluates                                                                                                                                |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Safety**        | Does the fix introduce breaking changes? Could it cause regressions? Does it preserve the application's existing behavior for legitimate inputs? |
| **Effectiveness** | Does the fix actually resolve the vulnerability? Will the SAST scanner stop flagging this finding after the fix is applied?                      |
| **Cleanliness**   | Does the fix meet code quality standards? Proper formatting, no extraneous changes, preserves existing comments?                                 |

An independent evaluator scores every fix on Safety, Effectiveness, and Cleanliness before it reaches a PR. Fixes that fail are retried with structured feedback or suppressed entirely. Scores that pass are included in the PR description so developers can see them. See [Fix Safety](/how-it-works/fix-safety) for the full rubric and process.

## Multi-Agent Fix Planning

Security fixes are not always single-file, single-line changes. A vulnerable dependency may require upgrading a library version in a manifest file, updating import statements in source files, and refactoring call sites that use changed APIs -- all as a single, atomic change.

Pixee decomposes complex fixes across specialized agents rather than cramming everything into a single AI prompt:

- **Version decision logic** -- determines which library version to target based on the vulnerability, framework compatibility, and runtime constraints
- **Source file identification** -- uses the vulnerability's dataflow evidence to identify which source files are affected
- **Manifest declaration updates** -- locates the exact line in the manifest file that needs to change

The fix plan itself is evaluated for quality before execution begins. If the plan is incomplete or inconsistent, it receives structured feedback and is refined. Plans that cannot reach acceptable quality are not executed.

The result is a single pull request that contains the manifest version bump AND the downstream source-file changes. No "upgrade succeeded, tests broken" half-states.

## Developer Experience

Fixes ship as native pull requests on GitHub, GitLab, Azure DevOps, or Bitbucket. A typical fix is 1-5 lines. Developers review, modify, or reject like any other code change. Your code review policies, CI/CD pipelines, SAST re-scanning, and branch protection rules all apply.

Standard `git revert` applies if any merged change needs to be undone. There is no runtime dependency -- removing Pixee leaves all previously merged fixes intact as standard code in your repository.

## Language and Scanner Coverage

| Coverage Type                   | Details                                                                                                                     |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| **Languages**                   | Java, Python, JavaScript/TypeScript, .NET/C#, Go, PHP                                                                       |
| **Native scanner integrations** | 12 (CodeQL, SonarQube, Checkmarx, Veracode, Snyk, Semgrep, AppScan, Polaris, GitLab SAST, Trivy, Datadog SAST, Arnica SAST) |
| **Universal SARIF**             | Any SARIF-producing scanner (50+ validated)                                                                                 |
| **Platforms**                   | GitHub, GitLab, Azure DevOps, Bitbucket                                                                                     |

Deterministic codemod coverage is deepest for Java (51+ codemods) and Python (60+ codemods), which together cover the most common enterprise vulnerability patterns. JavaScript/TypeScript, .NET, Go, and PHP have expanding codemod libraries supplemented by AI-powered generation for patterns not yet covered by deterministic rules.

Fixes are generated regardless of which scanner found the vulnerability. SCA findings flow through the same remediation pipeline as SAST findings -- see [SCA Capabilities](/platform/sca) for dependency-specific details.

## Frequently Asked Questions

### What is a good merge rate for automated security fixes?

Merge rate is measured on production pull requests, not theoretical accuracy. The rate reflects the combined effect of deterministic codemods for known patterns, independent quality evaluation for AI-generated fixes, and context-aware fix generation that matches codebase conventions. See [Fix Safety](/how-it-works/fix-safety) for current merge rate data.

### How do AI-generated code fixes get validated before merging?

Every fix passes through an independent quality evaluation scoring Safety (no breaking changes), Effectiveness (resolves the vulnerability), and Cleanliness (code quality). The evaluator is a separate inference call -- it does not share context with the generator. Fixes that fail are retried with structured feedback or suppressed. Developers see only pre-validated fixes.

### What is the scope of Pixee's fixes?

Pixee fixes SAST-identified security issues -- typically 1-5 lines applying established OWASP/SANS patterns. It uses deterministic codemods for known patterns and AI-powered generation with independent evaluation for novel patterns. All fixes are delivered as pull requests through your existing code review process.

### What happens when the AI generates a bad fix?

The independent fix evaluation gate catches it. Fixes that fail the Safety, Effectiveness, or Cleanliness evaluation are retried with structured feedback. If the fix still cannot pass after retries, it is suppressed entirely -- the developer never sees it. For fixes that pass evaluation and reach a PR, developers review and decide whether to merge. Standard `git revert` applies to anything merged that needs to be undone.

### Does Pixee fix dependency vulnerabilities too?

Yes. SCA findings flow through the same remediation pipeline as SAST findings. Dependency upgrades include both the manifest version bump and any downstream source-file changes in a single atomic PR. See [SCA Capabilities](/platform/sca) for full details.
