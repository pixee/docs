---
title: Checkmarx Integration
slug: /integrations/scanners/checkmarx
track: both
content_type: guide
seo_title: Checkmarx Integration with Pixee
description: Pixee integration with Checkmarx for automated triage and remediation, including adaptive handling for metadata-sparse SARIF.
sidebar_position: 2
---

# Checkmarx Integration

Pixee's Checkmarx integration triages CxSAST and CxOne findings and delivers remediation as pull requests -- even when Checkmarx SARIF exports contain minimal metadata. The dedicated Checkmarx handler compensates for sparse output by re-deriving context directly from the codebase, and includes Checkmarx-specific codemods for SQL and NoSQL injection.

## What Checkmarx Detects

Checkmarx (CxSAST and CxOne) is an enterprise SAST platform widely deployed in regulated industries including financial services, healthcare, and government.

Checkmarx detects:

- **SQL injection, XSS, path traversal, and authentication flaws** via deep static analysis
- **Broad CWE coverage** through commercial rule sets maintained by Checkmarx
- **Cross-language vulnerabilities** across many programming languages
- **Compliance-relevant findings** aligned with industry standards (OWASP, SANS, PCI DSS)

Checkmarx is known for thorough analysis with broad CWE coverage. It is also known for high false positive rates that require extensive manual tuning -- a pain point that grows with codebase scale and scanner deployment breadth.

## How Pixee Enhances Checkmarx

### Triage

Checkmarx findings are processed through Pixee's triage pipeline, which classifies each finding as TRUE_POSITIVE, FALSE_POSITIVE, or WONT_FIX with code-level justification.

The dedicated Checkmarx handler addresses a challenge unique to Checkmarx: metadata-sparse SARIF output.

**Adaptive handling for metadata-poor SARIF.** This is the key technical differentiator of the Checkmarx integration. Checkmarx's SARIF exports are notably sparse compared to other scanners -- minimal rule descriptions, no codeFlows, limited context about what the finding means or why it was flagged. Most downstream tooling struggles with this because triage accuracy depends on understanding the finding, not just its location.

Pixee's handler compensates. When Checkmarx SARIF provides minimal metadata, the adaptive triage pipeline re-derives context directly from the codebase. Rather than relying on the scanner to explain the finding, the system examines the actual code at the finding location, understands the surrounding context, and makes a triage decision based on what the code does -- not on what the scanner's sparse output says.

The result: Pixee's triage accuracy does not degrade when the scanner provides minimal context. Teams get the same quality of triage decisions regardless of how much metadata Checkmarx includes in its SARIF export.

### Remediation

True positive findings receive automated code fixes delivered as pull requests.

Pixee includes three Checkmarx-specific remediation codemods built for the most common Checkmarx finding categories:

| Codemod                | What It Fixes                             | Language   |
| ---------------------- | ----------------------------------------- | ---------- |
| SQL parameterization   | SQL injection via parameterized queries   | .NET       |
| SQL parameterization   | SQL injection via parameterized queries   | JavaScript |
| NoSQL parameterization | NoSQL injection via parameterized queries | JavaScript |

Beyond these dedicated codemods, Pixee's general-purpose codemod library and AI-powered MagicMods address additional vulnerability types identified by Checkmarx.

- Fixes match your team's code conventions
- Developers review and merge Pixee PRs through their standard workflow

## Finding Types

| Category             | Examples                          | Checkmarx-Specific Codemods |
| -------------------- | --------------------------------- | --------------------------- |
| SQL injection        | Parameterized query fixes         | .NET SQL, JavaScript SQL    |
| NoSQL injection      | Parameterized NoSQL fixes         | JavaScript NoSQL            |
| XSS                  | Output encoding, sanitization     | General codemods            |
| Path traversal       | Input validation                  | General codemods            |
| Authentication flaws | Session and auth misconfiguration | General codemods            |

## Setup

1. **Export Checkmarx findings in SARIF format** from CxSAST or CxOne.
2. **Connect your code repository to Pixee** via the appropriate platform integration (GitHub, GitLab, Azure DevOps, or Bitbucket).
3. **Upload Checkmarx SARIF** to Pixee (via CI/CD pipeline or direct upload).
4. **Pixee ingests and processes findings** through the triage and remediation pipeline -- compensating for sparse metadata automatically.
5. **Review and merge** Pixee-generated PRs in your normal workflow.

**Prerequisites:** Checkmarx CxSAST or CxOne license with SARIF export capability, Pixee connected to your SCM platform.

## Common False Positive Patterns Pixee Eliminates

- **SQL injection on parameterized code:** Findings flagged on code that already uses parameterized queries or ORM frameworks
- **XSS with framework-level encoding:** Findings where framework auto-escaping is present (React JSX, Django template engine, Angular sanitization)
- **Tuning-dependent suppressions:** Findings that would require manual Checkmarx tuning to suppress -- Pixee's triage handles this automatically with code-level justification
- **Test code at production severity:** Test fixtures and example files flagged alongside production code
- **Context-poor findings:** Findings where Checkmarx's sparse SARIF metadata makes manual review difficult -- Pixee re-derives context from the actual codebase

See [Integrations Overview](/integrations/overview) for the full scanner coverage matrix.

## FAQ

### Does Pixee replace Checkmarx?

No. Pixee complements Checkmarx by adding automated triage and remediation. Keep CxSAST or CxOne scanning exactly as it runs today. Pixee processes Checkmarx output and delivers classified findings and fixes.

### How does Pixee handle Checkmarx's sparse SARIF output?

Pixee's dedicated Checkmarx handler uses an adaptive strategy that re-derives context directly from the codebase when scanner metadata is minimal. Instead of depending on the scanner to explain the finding, Pixee examines the code itself. Triage accuracy does not degrade with sparse input.

### What Checkmarx-specific fixes does Pixee provide?

Pixee includes three dedicated codemods for Checkmarx findings: SQL parameterization for .NET, SQL parameterization for JavaScript, and NoSQL parameterization for JavaScript. Additional fixes are available through the general-purpose codemod library and AI-powered MagicMods.

### Does Pixee work with both CxSAST and CxOne?

Yes. Pixee ingests Checkmarx findings in SARIF format from both CxSAST and CxOne. The same triage and remediation pipeline processes findings regardless of which Checkmarx product generated them.
