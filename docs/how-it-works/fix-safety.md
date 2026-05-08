---
title: "Fix Safety & Validation"
slug: /how-it-works/fix-safety
track: both
content_type: guide
seo_title: "Fix Safety & Validation | How Pixee Prevents Bad Fixes"
description: Deterministic codemods, independent AI evaluation, and PR-only delivery. How Pixee validates fixes before they reach developers.
sidebar_position: 3
---

Pixee uses a deterministic-first, AI-second architecture with independent quality evaluation to ensure automated fixes do not break your code. Most fixes come from pre-built codemods that produce identical, zero-variance output every time. See [Fix Generation](/how-it-works/fix-generation) for the full codemod library. Fixes that require AI generation pass through a separate evaluation scoring Safety, Effectiveness, and Cleanliness before any developer sees them. Every change ships as a pull request -- never a direct commit -- preserving your existing code review, CI/CD, and SAST re-scanning gates. The measured result: a 76% merge rate on production deployments.

## How Fix Safety Works

Pixee's fix safety rests on independent validation layers, narrow scope by design, and preserved human authority at every stage.

## Deterministic vs. Probabilistic Fixes

This distinction is the single most important concept on this page. When technical evaluators understand it, the concern about AI-generated fixes fundamentally changes.

**Deterministic codemods:** Pre-built, rule-based code transformations encoding OWASP/SANS security patterns. Same input, same output, every time. Zero LLM involvement. Zero hallucination risk. The open-source codemod engines (codemodder-java, codemodder-python) are publicly inspectable -- your security team or auditors can read the transformation rules before deployment.

**AI-generated MagicMods:** Handle novel patterns where deterministic rules cannot reach -- custom framework wrappers, multi-file dataflow vulnerabilities, context-dependent sanitization. Every AI-generated fix earns its way through the evaluation pipeline.

| Dimension                       | Deterministic Codemods                                                         | AI-Generated MagicMods                                                |
| ------------------------------- | ------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| **Input/output predictability** | Identical output every time                                                    | Output varies based on context; constrained by dataflow-bounded input |
| **Scope**                       | Known vulnerability patterns (SQL injection, XSS, SSRF, deserialization, etc.) | Novel, custom, and multi-file patterns                                |
| **Hallucination risk**          | Zero                                                                           | Mitigated by independent evaluation and retry/suppression             |
| **Validation requirement**      | Pre-validated by design; open-source engines inspectable                       | Mandatory independent evaluation gate                                 |
| **LLM involvement**             | None                                                                           | Constrained generation with per-rule knowledge base guidance          |

Deterministic codemods carry zero AI risk. AI-generated fixes receive additional validation through the independent evaluation pipeline. Routing between modes is automatic -- no manual configuration.

## Independent Fix Evaluation

Every AI-generated fix passes through an independent quality gate before a developer sees it. This is the concrete mechanism behind the 76% merge rate.

**Separate inference call, not self-critique.** The evaluator runs as a structurally independent inference call -- separate context window, separate system prompt, separate scoring rubric -- not the same process that generated the fix. This prevents the "grading your own homework" failure mode that undermines single-pass AI systems.

**Three-dimension rubric:**

| Dimension         | What It Checks                                                    | Why It Matters                                              |
| ----------------- | ----------------------------------------------------------------- | ----------------------------------------------------------- |
| **Safety**        | No breaking changes, no regressions, no unintended side effects   | Prevents the fix from creating new problems                 |
| **Effectiveness** | Correctly resolves the security vulnerability                     | Prevents cosmetic changes that leave the vulnerability open |
| **Cleanliness**   | Proper formatting, no extraneous changes, preserves existing code | Prevents unnecessary diff noise that frustrates reviewers   |

**All three dimensions must pass.** This is not an aggregate score where a dangerous fix slides through because it scored well on formatting. A fix that fails Safety is rejected regardless of Effectiveness and Cleanliness scores.

**Structured feedback loop:** Fixes that fail evaluation receive specific reasoning and suggestions. The generator uses this feedback to produce a better fix. If a fix still cannot pass after retries, it is suppressed entirely -- with an explanation logged for debugging. The developer never sees a fix that failed the gate.

**Quality scores are visible.** When a fix passes evaluation and reaches the PR, the Safety, Effectiveness, and Cleanliness scores are included. Transparency builds trust over time.

## Your Existing Gates Still Apply

Fix evaluation is additional validation that happens before the PR reaches your existing quality controls. Pixee does not replace your gates -- it adds layers in front of them.

**What happens after Pixee creates the PR:**

1. **Code review** by the development team -- the same review process you apply to human-written code
2. **CI/CD pipeline execution** -- tests, builds, and any other automated checks you have configured
3. **SAST re-scanning** by the same tools that found the original vulnerability -- if the fix introduces new findings, they appear in the PR
4. **Branch protection rules** and merge requirements you have configured

Every Pixee change flows through your full approval pipeline. There is no mode, setting, or override that allows Pixee to commit directly to a branch. PR-only delivery is an architectural constraint, not an optional configuration.

Pixee does not replace your quality gates -- it adds validation layers before changes reach your existing review process.

## The 76% Merge Rate in Context

This number is measured merge behavior on production pull requests. It reflects developer trust -- engineers review the fix and choose to merge it.

**What it means:** Three out of four Pixee-authored fixes are accepted by development teams after human review.

**What it does not mean:** That 24% of fixes are harmful. Rejected fixes include cases where developers had a different preferred approach, the fix was correct but the team chose to address the issue differently, or the finding was deprioritized. A rejected PR has zero impact -- closing it discards the change.

**Why this number is trustworthy:** It reflects the combined output of deterministic reliability on common patterns (zero variance) plus validated AI generation on complex ones (independent evaluation gate). Fixes that cannot pass quality standards are suppressed before they reach a PR, so the 76% measures developer acceptance of pre-validated fixes -- not raw AI output.

## Narrow Scope, Lower Risk

Pixee fixes SAST-identified security issues. The typical fix is 1-5 lines of code adding input validation, parameterized queries, or safe API calls.

**What Pixee does:** Applies established OWASP/SANS remediation patterns to known vulnerability types.

**What Pixee does not do:** Write features. Generate business logic. Create new functionality. Refactor architectures. Perform open-ended code completion.

Security controls do not alter legitimate application behavior -- they block attacker traffic only. This narrow scope makes both independent evaluation and human review tractable.

## Rollback and Reversibility

- **Standard git revert.** Every Pixee change is a normal Git commit within a pull request. Standard git revert undoes any merged change. No special tooling required.
- **Full traceability.** All fixes are stored in Git history with complete context about what vulnerability was addressed and why the specific remediation was chosen.
- **No lock-in dependency.** If Pixee were removed entirely, all previously merged fixes remain as standard code in the repository. There is no runtime dependency on Pixee for merged code.
- **Pre-merge rejection is trivial.** Closing a PR without merging discards the proposed change with zero impact on the codebase.

## Audit Defensibility

For regulated industries, every Pixee fix creates a defensible audit record:

- Typed triage verdict (true positive, false positive, won't fix, suspicious) with code-level evidence
- Fix quality scores (Safety, Effectiveness, Cleanliness) on every PR
- Full Git history showing what changed, when, and why
- SAST re-scanning confirmation that the fix does not introduce new findings
- Developer approval recorded in the merge event

Compliance teams reviewing automated code changes need to see that the change was validated by independent evaluation, reviewed by a human, tested by CI/CD, and re-scanned by the same tools that found the original issue. Pixee's pipeline provides all four.

## Frequently Asked Questions

### Does automated remediation break existing code?

Pixee uses multiple independent validation layers to prevent breaking changes. Most fixes come from deterministic codemods with zero AI variance. AI-generated fixes pass independent evaluation scoring Safety, Effectiveness, and Cleanliness. Every change ships as a PR through your existing code review, CI/CD, and SAST re-scanning gates. Fixes that cannot pass quality standards are suppressed before developers see them.

### What happens if an automated fix introduces a bug?

Every Pixee change is a standard Git commit within a pull request. Standard git revert undoes any merged change -- no special tooling needed. Fixes are typically 1-5 lines, making review straightforward. There is no runtime dependency on Pixee for merged code, and closing a PR before merge discards the change with zero impact.

### How accurate are AI-generated security fixes?

Pixee achieves a 76% merge rate on production PRs -- three out of four fixes are accepted by development teams after human review. Many fixes use deterministic codemods with zero AI variance. AI-generated fixes pass an independent evaluation gate scoring Safety, Effectiveness, and Cleanliness. Fixes that cannot pass quality standards are suppressed, never shipped to developers.

### Is automated vulnerability remediation safe for production code?

Yes. Pixee's fixes are narrow-scope security changes (1-5 lines) applying established OWASP/SANS patterns, not general-purpose code generation. They pass multi-layer validation before reaching a PR, and your existing CI/CD, SAST re-scanning, and code review gates all apply. The PR-only delivery model is an architectural constraint -- there is no mode that allows direct commits.

### What is the confidence level on these fixes?

Every fix includes quality scores visible on the PR. Fixes must pass a three-dimension rubric (Safety, Effectiveness, Cleanliness) via an independent evaluation process before reaching developers. All three dimensions must pass independently -- a dangerous fix cannot slide through on aggregate scoring. Fixes that cannot meet standards after retries are suppressed with an explanation.
