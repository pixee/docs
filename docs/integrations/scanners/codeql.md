---
title: CodeQL Integration
slug: /integrations/scanners/codeql
track: both
content_type: guide
seo_title: CodeQL Integration with Pixee
description: Pixee integration with CodeQL for automated triage and remediation of GitHub Advanced Security findings.
sidebar_position: 3
---

# CodeQL Integration

Pixee's CodeQL integration ingests findings from GitHub Advanced Security, triages each one with code-level justification, and delivers remediation as pull requests. The dedicated CodeQL handler extracts dataflow paths (codeFlows), giving the triage engine full source-to-sink context -- not just the final finding location.

## What CodeQL Detects

CodeQL is GitHub's SAST engine, included with GitHub Advanced Security (GHAS). It performs deep semantic analysis to identify security vulnerabilities and code quality issues across your codebase.

CodeQL detects:

- **Dataflow vulnerabilities** -- SQL injection, cross-site scripting (XSS), path traversal, and other injection flaws with full source-to-sink traces
- **Security misconfigurations** -- insecure defaults, missing security headers, weak cryptographic settings
- **Code quality issues flagged as security-relevant** by CodeQL's query suites

CodeQL supports JavaScript, TypeScript, Python, Java, C/C++, C#, Go, Ruby, and Swift.

## How Pixee Enhances CodeQL

### Triage

CodeQL findings are processed through Pixee's triage pipeline, which classifies each finding as TRUE_POSITIVE, FALSE_POSITIVE, or WONT_FIX with a detailed, code-level justification.

The dedicated CodeQL handler provides deeper analysis than standard SARIF ingestion. Here is what it extracts and why it matters:

**codeFlows extraction.** CodeQL's SARIF output includes multi-step dataflow traces showing how data moves from a source (user input, external data) through intermediate steps to a sink (database query, HTML output). Pixee's handler extracts these complete codeFlows paths and passes them to the triage engine. The result: the triage decision considers the full data journey, not just the line where CodeQL flagged the finding. This distinction matters because a finding at line 47 might look dangerous in isolation but is provably safe when you see the sanitization at line 23.

**Non-standard SARIF handling.** CodeQL stores rule metadata on `tool.extensions` rather than `driver` -- a quirk that differs from how most other scanners structure their SARIF output. Pixee's handler accounts for this automatically, extracting `help.markdown` from rule metadata for rich vulnerability descriptions. Teams do not need to preprocess or normalize CodeQL SARIF before Pixee ingests it.

**Graceful fallback.** Real-world CodeQL output varies across versions and configurations. The handler degrades gracefully when SARIF fields like `full_description` are absent, maintaining triage coverage without manual intervention.

Each finding receives a classification with confidence score and audit-ready reasoning trail. Security teams review the triage output, not the raw scanner noise.

### Remediation

True positive findings receive automated code fixes delivered as pull requests.

Pixee generates fixes using a combination of deterministic codemods and AI-powered MagicMods for complex, codebase-specific scenarios. Every fix goes through multi-layer validation before reaching a developer's review queue.

- Pre-configured handlers cover common CodeQL rules
- Fixes match your team's code conventions -- naming patterns, preferred libraries, existing security utilities
- Developers review and merge Pixee PRs through the standard GitHub workflow

## Finding Types

| Category                         | Examples                           | codeFlows Extraction              |
| -------------------------------- | ---------------------------------- | --------------------------------- |
| Dataflow vulnerabilities         | SQL injection, XSS, path traversal | Yes -- full source-to-sink traces |
| Security misconfigurations       | Insecure defaults, missing headers | No (location-based findings)      |
| Code quality (security-relevant) | CodeQL query suite findings        | Varies by rule                    |

## Setup

1. **Enable CodeQL scanning** in your GitHub repository via GitHub Advanced Security.
2. **Install the Pixee GitHub App** on your organization or selected repositories.
3. **Pixee automatically ingests CodeQL findings** via the GHAS API or SARIF upload -- no manual export required.
4. **Configure triage preferences** in `PIXEE.yaml` (optional) to tune classification behavior.
5. **Review and merge** Pixee-generated PRs in your normal GitHub workflow.

**Prerequisites:** GitHub Advanced Security license, Pixee GitHub App installed.

## Common False Positive Patterns Pixee Eliminates

- **Sanitized sinks:** Dataflow traces that terminate in sinks protected by framework-level sanitization (CodeQL cannot always resolve sanitization applied by middleware or security libraries)
- **Informational findings:** Security-relevant code quality findings that are informational, not exploitable in the actual runtime environment
- **Test code at production severity:** Findings in test fixtures, example code, and documentation snippets flagged at production severity levels
- **Low-precision rules in specific contexts:** Rules with high recall but low precision in certain language or framework configurations

See [Integrations Overview](/integrations/overview) for the full scanner coverage matrix.

## FAQ

### Does Pixee replace CodeQL or GitHub Advanced Security?

No. Pixee complements CodeQL by adding automated triage and remediation on top of your existing GHAS deployment. CodeQL continues scanning exactly as before. Pixee processes the output.

### What is codeFlows extraction?

CodeQL SARIF includes multi-step dataflow traces showing how data moves from source to sink. Pixee's dedicated handler extracts these traces to give the triage engine full context -- the complete data journey, not just the flagged line. This leads to more accurate triage decisions, especially for injection-class vulnerabilities.

### Do I need to export CodeQL results manually?

No. Pixee's GitHub integration ingests CodeQL findings automatically via the GHAS API. If you prefer, you can also upload CodeQL SARIF directly. Either path feeds into the same triage and remediation pipeline.
