---
title: Veracode Integration
slug: /integrations/scanners/veracode
track: both
content_type: guide
seo_title: Veracode Integration with Pixee
description: Pixee integration with Veracode for automated triage and remediation of SAST findings.
sidebar_position: 15
---

# Veracode Integration

Pixee integrates natively with Veracode to triage SAST findings and deliver remediation as pull requests. Pixee sits downstream, classifying each finding as true positive, false positive, or won't-fix with code-level justification, then generating fixes for confirmed vulnerabilities.

## What Veracode Detects

Veracode is a leading cloud-native application security platform widely deployed in regulated industries including financial services, healthcare, and government. Its centralized cloud scanning model -- code is uploaded to Veracode's cloud for analysis -- provides broad coverage without requiring local scanning infrastructure.

Veracode detects:

- **Static Application Security Testing (SAST)** -- broad coverage of OWASP Top 10 and CWE categories including injection flaws, cross-site scripting, authentication weaknesses, and insecure cryptography
- **Software Composition Analysis (SCA)** -- open-source dependency vulnerabilities and license risk
- **Dynamic Application Security Testing (DAST)** -- runtime vulnerability detection against deployed applications
- **Secrets detection** -- hardcoded credentials and API keys
- **Infrastructure as Code (IaC) misconfigurations**

## How Pixee Enhances Veracode

### Triage

Veracode findings are processed through Pixee's triage pipeline, which classifies each finding as TRUE_POSITIVE, FALSE_POSITIVE, or WONT_FIX with a detailed justification and confidence score.

The dedicated Veracode handler extracts scanner-specific metadata from Veracode's SARIF output, providing the triage engine with the context it needs for accurate classification. This reduces the manual triage burden on AppSec teams who currently review Veracode results in the Veracode portal -- a process that consumes hours of analyst time per scan cycle.

Each classified finding includes an audit-ready justification trail explaining the reasoning behind the triage decision.

### Remediation

True positive findings receive automated code fixes delivered as pull requests. Pixee generates fixes using deterministic codemods and AI-powered MagicMods for complex, codebase-specific scenarios.

Veracode's own "Veracode Fix" provides AI-assisted remediation suggestions, but it does not deliver merged pull requests at scale. Pixee closes that gap: findings move from classification to fix to developer review in one pipeline. Developers review and merge Pixee PRs through their standard workflow.

For the full list of vulnerability types Pixee triages and fixes, see [What Pixee Fixes](/platform/what-pixee-fixes).

## Setup

1. **Connect Veracode credentials** in Pixee settings (Helm values for Enterprise Server, or SaaS configuration).
2. **Configure Veracode SARIF export** or use Pixee's native Veracode integration to ingest findings directly.
3. **Connect your code repository** (GitHub, GitLab, Azure DevOps, or Bitbucket).
4. **Pixee processes findings** automatically through the triage and remediation pipeline.
5. **Review and merge** Pixee-generated PRs in your normal development workflow.

**Prerequisites:** Veracode account with SAST scan results, Pixee account with connected repository.

## Common False Positive Patterns Pixee Eliminates

- **Parameterized query false positives:** Veracode flags SQL injection on code that already uses parameterized APIs or ORMs -- Pixee's triage verifies the actual query construction
- **Sanitized input in complex flows:** Veracode's static analysis cannot always trace sanitization through complex control flow; Pixee investigates security controls in the actual codebase
- **Test code at production severity:** Pixee distinguishes test fixtures, example code, and documentation snippets from production code
- **Framework-mitigated findings:** Code protected by framework-level security controls (Spring Security, Django middleware) that Veracode's static analysis cannot resolve

See [Integrations Overview](/integrations/overview) for the full scanner coverage matrix.
