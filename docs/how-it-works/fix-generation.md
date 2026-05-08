---
title: Fix Generation
slug: /how-it-works/fix-generation
track: both
content_type: guide
seo_title: "How Fix Generation Works | Codemods + AI Remediation"
description: "How Pixee generates security fixes: deterministic codemods for known patterns, AI-powered MagicMods for novel scenarios, and independent quality evaluation."
sidebar_position: 2
---

Pixee generates security fixes through a hybrid-intelligence engine: 120+ deterministic codemods handle known vulnerability patterns with zero AI variance, while AI-powered MagicMods handle novel and complex scenarios using dataflow-bounded context and per-rule knowledge base guidance. Every fix -- deterministic or AI-generated -- passes through an independent quality evaluation scoring Safety, Effectiveness, and Cleanliness before reaching a pull request. Developers see only pre-validated fixes. See [Fix Safety](/how-it-works/fix-safety) for merge rate data.

Remediation is one of two co-equal capabilities in Pixee's Agentic Security Engineering Platform. The other is [Triage Automation](/how-it-works/triage-engine), which classifies findings as true or false positives with structured evidence. Together they close the loop from "scanner found something" to "vulnerability is fixed."

## Fix Generation Pipeline

Every scanner finding that passes triage as a true positive enters the same fix pipeline, regardless of which scanner detected it or whether the fix uses deterministic or AI-powered generation.

**End-to-end flow:**

1. **Context gathering** -- classifies dataflow quality on a four-tier scale, follows taint propagation across files, highlights vulnerable regions with inline markers, and adapts context windows to file size
2. **Route decision** -- known pattern routes to a deterministic codemod; novel or complex pattern routes to an AI-powered MagicMod
3. **Fix planning** (complex/multi-file fixes) -- specialized agents decompose the fix into coordinated manifest changes, source file edits, and declaration updates
4. **Fix generation** -- codemod applies an AST or regex transformation (deterministic); MagicMod generates a fix with dataflow-bounded context and per-rule guidance
5. **Fix evaluation** -- a separate inference call scores the fix on Safety, Effectiveness, and Cleanliness. Fixes that fail are retried with structured feedback or suppressed
6. **PR creation** -- the validated fix plus metadata, diff rationale, and quality scores are delivered as a pull request

The same evaluation gate applies regardless of whether the fix was deterministic or AI-generated. The pipeline handles both SAST and [SCA findings](/how-it-works/sca-pipeline).

## Deterministic Codemods

Codemods are pre-built, rule-based code transformations encoding OWASP/SANS security patterns. No LLM is involved. Same input, same output, every time.

**Scale:** 120+ codemods across Java and Python. The open-source engines -- codemodder-java (51 core codemods) and codemodder-python (60+ core codemods) -- are publicly inspectable on GitHub, with additional JavaScript/TypeScript coverage.

**Fix types covered:**

- SQL injection parameterization
- SSRF prevention
- Insecure deserialization (PyYAML hardening, defused XML)
- Weak cryptography (secure random, JWT decode verification)
- Insecure temp file handling
- SSL/TLS protocol upgrades
- Security hardening patterns from OWASP/SANS

**Why deterministic matters:**

- **Zero hallucination risk.** The transformation is a fixed rule, not a generated response. There is no variance between runs.
- **Auditor-inspectable.** The open-source codemod engines let customers and auditors read the transformation rules before deployment.
- **Cost-effective at scale.** Codemods run in sub-second time with zero inference cost. This keeps per-finding cost bounded, leaving AI budget for genuinely novel cases.

Codemods handle known, solved patterns without AI involvement.

## AI-Powered MagicMods

MagicMods fire when no deterministic codemod matches the finding. They handle the scenarios that rule-based systems cannot reach: custom framework wrappers, multi-file dataflow vulnerabilities, context-dependent sanitization, and novel patterns.

**MagicMod architecture:**

- **Dataflow-bounded context.** The LLM receives only the code relevant to the vulnerability's dataflow path. This precision controls token cost and provides focused context.
- **Per-rule knowledge base guidance.** Each scanner rule has associated remediation knowledge. The LLM receives rule-specific security advice, not generic guidance.
- **Per-project PIXEE.yaml policy.** MagicMods respect project-level configuration files specifying your coding conventions, preferred imports, and framework choices. AI-generated fixes match your team's style.
- **Scanner-aware dispatchers.** Dispatchers for 8+ scanner types (Semgrep, CodeQL, Sonar, Snyk, AppScan, Polaris, DefectDojo, Trivy) understand each tool's output format and rule semantics. A Semgrep finding is processed differently than a Checkmarx finding because the available metadata differs.

Every MagicMod fix passes through the same independent evaluation gate that all fixes pass.

## Context Gathering

Fix quality is bounded by what the LLM can see. Context gathering is the engineering that controls this boundary.

**4-tier dataflow quality classification:**

| Tier                   | Description                                             | Gathering Strategy                                                    |
| ---------------------- | ------------------------------------------------------- | --------------------------------------------------------------------- |
| **Strong Multi-File**  | High-confidence taint propagation across multiple files | Traces full cross-file dataflow; includes all files in the taint path |
| **Strong Single-File** | High-confidence dataflow within a single file           | Full file context with highlighted vulnerable region                  |
| **Weak**               | Partial or low-confidence dataflow information          | Targeted excerpts around the flagged location                         |
| **Single-Location**    | Only the flagged line, no dataflow available            | Surrounding context with heuristic file matching                      |

**Key capabilities:**

- Follows SARIF-based taint propagation across files
- Highlights the vulnerable region with inline markers so the LLM knows exactly where the problem is
- Adapts between whole-file and targeted excerpts based on file size
- Merges consecutive vulnerable regions in the same file to reduce token cost
- Fuzzy file matching finds related files not explicitly named in the dataflow

This context layer is shared between triage and remediation paths. The same classification that drives triage verdict accuracy also drives fix quality.

## Multi-Agent Fix Planning

Some security fixes span multiple files. A vulnerable dependency may require upgrading the library version in a manifest file, updating import statements in source files, and refactoring call sites that use changed APIs -- all as a single, atomic change.

Pixee decomposes complex fixes across specialized agents rather than cramming everything into a single AI prompt:

- **Version decision logic** -- determines which library version resolves the vulnerability while maintaining compatibility
- **Source file identification** -- uses the vulnerability's dataflow evidence to identify which source files need edits
- **Manifest declaration updates** -- locates the exact line in the manifest file that needs to change

**Iterative refinement:** The fix plan is evaluated for quality before execution begins. Plans that are incomplete or inconsistent receive structured feedback and are refined. Plans that cannot reach acceptable quality are not executed.

**Why this matters:** Multi-file security fixes are where single-pass AI code generation consistently fails. The model forgets the manifest, bumps the dependency without updating imports, or edits the wrong file. Structured planning with specialized agents prevents these failure modes.

The result is an atomic PR: manifest change plus source-file refactoring plus declaration updates in a single pull request. No "upgrade succeeded, tests broken" half-states.

## Fix Evaluation

Every generated fix passes through an independent quality gate before a developer sees it. Bad fixes are rejected, not shipped.

**Three-dimension rubric:**

| Dimension         | What It Checks                                                    | Failure Example                                            |
| ----------------- | ----------------------------------------------------------------- | ---------------------------------------------------------- |
| **Safety**        | No breaking changes, no regressions, no unintended side effects   | Fix changes the API signature, breaking callers            |
| **Effectiveness** | Correctly resolves the security vulnerability                     | Fix adds validation but misses the actual injection point  |
| **Cleanliness**   | Proper formatting, no extraneous changes, preserves existing code | Fix reformats the entire file or removes existing comments |

**Architectural independence:** The evaluator runs as a separate inference call -- the generator does not grade its own work. This is not self-critique from the same model. The separation prevents the "grading your own homework" failure mode.

**Retry and suppression:** Fixes that fail receive specific reasoning and suggestions. The generator uses this feedback to produce a better fix. If a fix still cannot pass after retries, it is suppressed with an explanation -- the developer never sees it.

For the full trust analysis, see [Fix Safety and Validation](/how-it-works/fix-safety).

## What Developers See

The end product is a standard pull request in GitHub, GitLab, Azure DevOps, or Bitbucket. There is no new tool to learn and no context-switching.

**A typical Pixee PR includes:**

- **Code diff** -- usually 1-5 lines adding input validation, parameterized queries, or safe API calls
- **Vulnerability context** -- what the scanner found and why it matters
- **Quality scores** -- Safety, Effectiveness, and Cleanliness scores from the evaluation gate
- **Fix rationale** -- why this specific remediation approach was chosen

Developers review, modify, reject, or merge like any other code change. Standard git revert applies to any merged change. There is no runtime dependency on Pixee for merged code -- if Pixee were removed, all previously merged fixes remain as standard code in the repository.

## Frequently Asked Questions

### How do AI-generated code fixes get validated before merging?

Every fix passes through an independent quality evaluation scoring three dimensions: Safety (no breaking changes), Effectiveness (resolves the vulnerability), and Cleanliness (code quality). The evaluator runs as a separate inference call -- the generator does not grade its own work. Fixes that fail are retried with structured feedback or suppressed entirely. Developers see only fixes that have passed this gate.

### What is a good merge rate for automated security fixes?

Merge rate reflects the combined quality of deterministic codemods (zero variance on known patterns), AI-generated fixes (constrained generation with independent evaluation), and the suppression of fixes that cannot pass quality gates. See [Fix Safety](/how-it-works/fix-safety) for current merge rate data.

### What is the difference between codemods and AI-generated fixes?

Deterministic codemods are pre-built, rule-based transformations that produce identical output every time with zero AI involvement. They handle known patterns like SQL injection parameterization and SSRF prevention. AI-powered MagicMods handle novel patterns where deterministic rules cannot reach, using LLM-based generation with dataflow-bounded context and independent quality evaluation. The system routes each vulnerability to the appropriate mode automatically.

### Does Pixee respect my team's coding conventions?

Yes. AI-generated fixes use per-project PIXEE.yaml policy files that specify coding conventions, preferred imports, and framework choices. Deterministic codemods follow OWASP/SANS standard patterns. All fixes can be modified by developers before merging -- they are standard PRs with full diff visibility.

### What is the failure mode for AI-generated fixes?

When an AI-generated fix does not meet quality standards, it is retried with structured feedback from the evaluator. If it still cannot pass after retries, it is suppressed with an explanation -- the developer never sees it. No fix reaches a pull request without passing the independent evaluation gate. Developers always have final authority: they can modify, reject, or revert any merged change through standard Git operations.
