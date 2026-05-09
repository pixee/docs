---
title: Remediation
slug: /platform/remediation
track: both
content_type: guide
seo_title: "Automated Vulnerability Remediation | 76% Merge Rate"
description: How Pixee generates security fixes using deterministic codemods and AI-powered fixes with independent quality evaluation.
sidebar_position: 4
---

Pixee generates validated security fixes and delivers them as pull requests. The hybrid-intelligence engine routes each vulnerability to the best fix method: deterministic codemods handle known patterns with zero AI variance, while AI-powered fixes handle novel and complex scenarios. Every fix passes independent quality evaluation before reaching a developer. Across production deployments, 76% of Pixee-generated fixes are merged by development teams after human review.

Remediation is co-equal with [triage](/platform/triage). Triage determines what is real; remediation fixes what is real.

## Hybrid Intelligence Model

Pixee uses two fundamentally different fix engines, routed automatically based on vulnerability type:

| Engine | How It Works | When It Fires | Risk Profile |
|---|---|---|---|
| **Deterministic codemods** | Pre-built, rule-based transformations encoding OWASP/SANS patterns | Known patterns: SQL injection parameterization, SSRF prevention, insecure deserialization, weak cryptography, insecure temp files, SSL/TLS upgrades | Zero hallucination risk. Same input, same output, every time. |
| **AI-powered fixes** | Constrained AI generation with dataflow-bounded context and per-rule knowledge base guidance | Custom frameworks, multi-file dataflow vulnerabilities, novel patterns, context-dependent sanitization | AI-generated, independently evaluated before reaching a PR. |

Routing is automatic. The system checks whether a deterministic codemod exists for the vulnerability type. If yes, the codemod fires — sub-second, zero LLM cost. If no deterministic rule handles it, an AI-powered fix is generated using scanner-aware context.

**Open-source engines.** The deterministic codemod engines (codemodder-java, codemodder-python) are publicly inspectable. Customers and auditors can read the transformation rules before trusting them.

**Native scanner support.** Pixee extracts maximum metadata from each scanner's native output format, normalizing findings for consistent downstream processing regardless of source scanner. Native integrations benefit from richer metadata than generic SARIF ingestion.

## Context Gathering

Fix quality is bounded by what the system can see. Context gathering adapts based on the quality and completeness of dataflow evidence available for each finding. Pixee evaluates whether the full taint path from source to sink is traceable and adjusts context accordingly — tracing full cross-file dataflow when available, and using targeted excerpts when evidence is limited.

Key capabilities: follows SARIF-based taint propagation across files, highlights the vulnerable region with inline markers, adapts between whole-file and targeted excerpts based on file size, and merges consecutive vulnerable regions to reduce token cost.

## Fix Evaluation

Every generated fix passes through an independent quality gate before a developer sees it. Bad fixes are rejected, not shipped.

**Three-dimension rubric:**

| Dimension | What It Checks | Why It Matters |
|---|---|---|
| **Safety** | No breaking changes, no regressions, no unintended side effects | Prevents the fix from creating new problems |
| **Effectiveness** | Correctly resolves the security vulnerability | Prevents cosmetic changes that leave the vulnerability open |
| **Cleanliness** | Proper formatting, no extraneous changes, preserves existing code | Prevents unnecessary diff noise that frustrates reviewers |

**Architectural independence.** The evaluator runs as a separate inference call — the generator does not grade its own work. This is not self-critique from the same model. The separation prevents the "grading your own homework" failure mode.

**Retry and suppression.** Fixes that fail evaluation receive specific reasoning and suggestions. The generator uses this feedback to produce a better fix. If a fix still cannot pass after retries, it is suppressed entirely — the developer never sees it.

**Quality scores are visible.** When a fix passes evaluation and reaches a PR, the Safety, Effectiveness, and Cleanliness scores are included in the PR description. Transparency builds trust over time.

## Multi-Agent Fix Planning

Some security fixes span multiple files. A vulnerable dependency may require upgrading the library version in a manifest file, updating import statements, and refactoring call sites — all as a single, atomic change.

Pixee decomposes complex fixes across specialized agents rather than cramming everything into a single AI prompt:

- **Version decision logic** — determines which library version resolves the vulnerability while maintaining compatibility
- **Source file identification** — uses the vulnerability's dataflow evidence to identify which source files need edits
- **Manifest declaration updates** — locates the exact line in the manifest file that needs to change

The fix plan is evaluated for quality before execution begins. Plans that are incomplete or inconsistent receive structured feedback and are refined. Plans that cannot reach acceptable quality are not executed.

The result is an atomic PR: manifest change plus source-file refactoring in a single pull request. No "upgrade succeeded, tests broken" half-states.

## Developer Experience

Fixes ship as native pull requests on GitHub, GitLab, Azure DevOps, or Bitbucket. A typical Pixee PR includes:

- **Code diff** — usually 1-5 lines adding input validation, parameterized queries, or safe API calls
- **Vulnerability context** — what the scanner found and why it matters
- **Quality scores** — Safety, Effectiveness, and Cleanliness scores from the evaluation gate
- **Fix rationale** — why this specific remediation approach was chosen

Developers review, modify, reject, or merge like any other code change. Your code review policies, CI/CD pipelines, SAST re-scanning, and branch protection rules all apply.

Standard `git revert` applies if any merged change needs to be undone. There is no runtime dependency — removing Pixee leaves all previously merged fixes intact as standard code in your repository.

## Language and Scanner Coverage

| Coverage Type | Details |
|---|---|
| **Languages** | Java, Python, JavaScript/TypeScript, .NET/C#, Go, Ruby, PHP, Kotlin, Rust, Scala, Swift + IaC (Terraform, Dockerfile, K8s/Helm, CloudFormation) |
| **Native scanner integrations** | 13 (CodeQL, SonarQube, Checkmarx, Veracode, Snyk Code, Semgrep, AppScan, Polaris, Fortify, Contrast, GitLab SAST, GitLab SCA, Trivy) |
| **Universal SARIF** | Any SARIF-producing scanner (50+ validated) |
| **Platforms** | GitHub, GitLab, Azure DevOps, Bitbucket |

Deterministic codemod coverage is deepest for Java and Python. JavaScript/TypeScript, .NET, Go, and PHP have expanding codemod libraries supplemented by AI-powered generation for patterns not yet covered by deterministic rules.

SCA findings flow through the same remediation pipeline as SAST findings — see [SCA](/platform/sca) for dependency-specific details.
