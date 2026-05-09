---
title: Datadog SAST Integration
slug: /integrations/scanners/datadog-sast
track: both
content_type: guide
seo_title: Datadog SAST Integration with Pixee
description: Pixee integration with Datadog Static Analysis for automated triage and remediation of SAST findings.
sidebar_position: 16
---

# Datadog SAST Integration

Pixee integrates with Datadog Static Analysis to triage findings and deliver remediation as pull requests. Datadog's SAST scanning surfaces code-level security issues alongside your observability data; Pixee adds triage to separate exploitable vulnerabilities from noise and remediation to deliver validated fixes as PRs.

## How Pixee Enhances Datadog SAST

### Triage

Datadog Static Analysis findings flow through Pixee's triage pipeline, which classifies each finding as TRUE_POSITIVE, FALSE_POSITIVE, or WONT_FIX with code-level justification. The triage engine investigates the actual codebase — evaluating dataflow, security controls, and surrounding context — rather than relying on the rule match alone.

Teams running Datadog for observability and security in a unified platform can use Pixee to close the loop from finding detection to validated fix — without leaving the pull request workflow.

### Remediation

Confirmed vulnerabilities receive automated code fixes delivered as pull requests. Pixee generates fixes using deterministic codemods for known vulnerability patterns and AI-powered fixes for complex or codebase-specific cases.

For the full list of vulnerability types Pixee triages and fixes, see [What Pixee Fixes](/platform/what-pixee-fixes).

## Setup

1. **Connect your code repository to Pixee** via the appropriate platform integration — see [Connect Source Control](/getting-started/source-control) for GitHub, GitLab, Azure DevOps, and Bitbucket.
2. **Configure Datadog Static Analysis to export SARIF output** and deliver it to Pixee via the SARIF upload endpoint or CI/CD pipeline step.
3. **Review and merge** Pixee-generated PRs in your normal workflow.

**Prerequisites:** Datadog Static Analysis configured for your repositories, Pixee connected to your SCM platform.

See [Integrations Overview](/integrations/overview) for the full scanner coverage matrix.
