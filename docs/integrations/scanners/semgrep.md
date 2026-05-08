---
title: Semgrep Integration
slug: /integrations/scanners/semgrep
track: both
content_type: guide
seo_title: Semgrep Integration with Pixee
description: Pixee integration with Semgrep for automated triage and remediation of OSS and Pro rule findings.
sidebar_position: 11
---

# Semgrep Integration

Pixee's Semgrep integration processes findings from both Semgrep OSS and Semgrep Pro through automated triage and remediation. The dedicated Semgrep handler extracts rule metadata for accurate classification, then delivers fixes as pull requests.

## What Semgrep Detects

Semgrep is a lightweight, fast SAST scanner with a large and growing rule library. Teams adopt it for its speed, pattern-based rule syntax, and developer-friendly workflow.

Semgrep detects:

- **OWASP Top 10 vulnerabilities** -- injection, broken authentication, XSS, insecure deserialization, and more
- **Language-specific security rules** from both OSS and Pro rule sets
- **Custom organizational rules** written in Semgrep's pattern syntax for team-specific security policies
- **Code quality issues with security implications** -- hardcoded secrets, weak cryptographic usage, deprecated API calls

Semgrep supports Python, JavaScript/TypeScript, Java, Go, Ruby, C#, PHP, Kotlin, Swift, and more. Rules run via Semgrep CLI (open source) or Semgrep Code (cloud platform).

## How Pixee Enhances Semgrep

### Triage

Semgrep findings are processed through Pixee's triage pipeline, which classifies each finding as TRUE_POSITIVE, FALSE_POSITIVE, or WONT_FIX with code-level justification and a confidence score.

The dedicated Semgrep handler provides scanner-specific metadata extraction:

**Rule metadata extraction.** Pixee's handler extracts `fullDescription.text` rule metadata from Semgrep's SARIF output, giving the triage engine the rule explanation alongside the finding. This context helps the triage pipeline distinguish between high-severity exploitable findings and informational warnings that share the same rule ID.

**OSS and Pro rule support.** The handler processes findings from both Semgrep OSS and Semgrep Pro rule sets. Whether your team uses the community rules, the commercial Pro rules, or a mix, findings flow through the same triage pipeline.

**Custom rule support.** Custom Semgrep rules that produce SARIF output work with Pixee automatically. Your organization's custom security policies are triaged and remediated through the same pipeline as standard rules -- no additional configuration required.

Each finding receives a classification with reasoning trail suitable for audit documentation. Security teams can review the triage decisions, not just the raw output.

### Remediation

True positive findings receive automated code fixes delivered as pull requests.

Pixee generates fixes using deterministic codemods and AI-powered MagicMods. The deterministic codemods handle standard security patterns with zero LLM dependency. MagicMods address complex, codebase-specific scenarios where the fix requires understanding your application's architecture and conventions.

- Fixes match your team's code conventions -- Pixee generates fixes that use your existing libraries and follow your patterns
- Semgrep identifies what is wrong; Pixee delivers the fix as a PR
- Developers review Pixee PRs through the same workflow they use for all code changes

## Finding Types

| Category                         | Examples                                  | Coverage               |
| -------------------------------- | ----------------------------------------- | ---------------------- |
| OWASP Top 10                     | SQL injection, XSS, broken authentication | OSS + Pro rules        |
| Language-specific security       | Framework misuse, insecure defaults       | Per-language rule sets |
| Custom organizational rules      | Team-specific patterns and policies       | Custom Semgrep rules   |
| Code quality (security-relevant) | Hardcoded secrets, weak crypto            | OSS + Pro rules        |

## Setup

1. **Run Semgrep** on your repository via Semgrep CLI, CI/CD integration, or Semgrep Code (cloud).
2. **Export results in SARIF format** using `semgrep --sarif` (CLI) or configure SARIF export in Semgrep Code.
3. **Connect your code repository to Pixee** via the appropriate platform integration (GitHub, GitLab, Azure DevOps, or Bitbucket).
4. **Pixee ingests Semgrep SARIF** and processes findings through the triage and remediation pipeline.
5. **Review and merge** Pixee-generated PRs in your normal workflow.

**Prerequisites:** Semgrep installed or Semgrep Code account, Pixee connected to your SCM platform.

## Common False Positive Patterns Pixee Eliminates

- **Low-severity OSS rules on common patterns:** Rules that fire on widespread coding patterns without evaluating whether the specific instance is exploitable
- **Per-file duplication noise:** The same rule firing on multiple locations across files without prioritization or deduplication
- **Framework-mitigated findings:** Code protected by middleware, security libraries, or framework-level controls that Semgrep's pattern matching cannot resolve
- **Test code flagged at production severity:** Test fixtures, example code, and mock data triggering rules intended for production code
- **Stale API warnings:** Generic rules that lack language-version awareness, flagging deprecated API usage on code that has already been migrated

See [Integrations Overview](/integrations/overview) for the full scanner coverage matrix.

## FAQ

### Does Pixee replace Semgrep?

No. Pixee complements Semgrep by adding automated triage and remediation. Keep running Semgrep exactly as you do today. Pixee processes Semgrep's output and delivers classified findings and fixes.

### Does Pixee work with both Semgrep OSS and Semgrep Pro?

Yes. Pixee's dedicated Semgrep handler supports both Semgrep OSS and Pro rule output. Findings from either rule set are processed through the same triage and remediation pipeline.

### What about my custom Semgrep rules?

Custom Semgrep rules that produce SARIF output work with Pixee automatically. Findings from custom rules are triaged and remediated through the same pipeline as standard rules. No additional configuration is needed.

### How does Pixee handle Semgrep's high-volume output?

Pixee's triage engine classifies each finding with a code-level justification and confidence score. Findings classified as false positives or won't-fix are separated from true positives, so developers see only actionable findings with fixes ready for review. The volume problem becomes a solved problem.
