---
title: Arnica Integration
slug: /integrations/scanners/arnica
track: both
content_type: guide
seo_title: Arnica Integration with Pixee
description: Pixee integration with Arnica for automated triage and remediation of SAST findings.
sidebar_position: 15
---

# Arnica Integration

Pixee integrates with Arnica to triage SAST findings and deliver remediation as pull requests. Arnica's continuous security scanning surfaces code vulnerabilities across your repositories; Pixee adds the triage layer to separate exploitable findings from noise, and the remediation layer to deliver validated fixes.

## How Pixee Enhances Arnica

### Triage

Arnica findings flow through Pixee's triage pipeline, which classifies each finding as TRUE_POSITIVE, FALSE_POSITIVE, or WONT_FIX with code-level justification. The triage engine investigates the actual codebase — checking dataflow, security controls, and context — rather than relying on the rule match alone.

Each classification includes a structured justification suitable for audit documentation. Security teams can review triage decisions, not just raw scanner output.

### Remediation

Confirmed vulnerabilities receive automated code fixes delivered as pull requests. Pixee generates fixes using deterministic codemods for known vulnerability patterns and AI-powered fixes for complex or codebase-specific cases.

For the full list of vulnerability types Pixee triages and fixes, see [What Pixee Fixes](/platform/what-pixee-fixes).

## Setup

1. **Connect your code repository to Pixee** via the appropriate platform integration — see [Connect Source Control](/getting-started/source-control) for GitHub, GitLab, Azure DevOps, and Bitbucket.
2. **Configure Arnica to export findings in SARIF format** and deliver them to Pixee via the SARIF upload endpoint or CI/CD pipeline step.
3. **Review and merge** Pixee-generated PRs in your normal workflow.

**Prerequisites:** Arnica configured for your repositories, Pixee connected to your SCM platform.

See [Integrations Overview](/integrations/overview) for the full scanner coverage matrix.
