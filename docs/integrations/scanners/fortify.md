---
title: Fortify Integration
slug: /integrations/scanners/fortify
track: both
content_type: guide
seo_title: Fortify (OpenText / Micro Focus) Integration with Pixee
description: Pixee integration with Fortify SAST for automated triage and remediation. Reduces backlog burden in regulated and government environments.
sidebar_position: 6
---

# Fortify Integration

Pixee integrates with Fortify to triage SAST findings and deliver remediation as pull requests. Fortify is widely deployed in government, defense, and regulated industries where long-standing contracts make it the entrenched SAST tool — and where finding backlogs frequently accumulate faster than manual triage can keep pace. Pixee classifies findings by exploitability and generates the code fixes Fortify does not produce. Your Fortify scans continue running as configured.

> Fortify has changed corporate hands over the years (HP → HPE → Micro Focus → OpenText). Pixee works with Fortify regardless of which logo is on your license agreement.

## What Fortify Detects

- OWASP Top 10 and CWE categories across 25+ programming languages
- Dataflow vulnerabilities with source-to-sink taint analysis
- Security misconfigurations
- Quality and reliability issues flagged as security-relevant
- Custom rule support for organization-specific patterns

Fortify produces SARIF output via its FPR-to-SARIF conversion tools, enabling integration with downstream platforms.

## How Pixee Enhances Fortify

### Triage

Fortify findings in government and financial services environments often accumulate into large backlogs because manual triage cannot keep pace with scan volume. Pixee's triage pipeline classifies each finding by exploitability, reducing the manual review burden.

Fortify's rich dataflow analysis provides source-to-sink traces that Pixee's triage engine can leverage for more accurate exploitability assessment. When the SARIF output includes those traces, the triage decision considers the full data journey, not just the line where Fortify flagged the finding.

### Remediation

Fortify identifies vulnerabilities but does not generate automated code fixes. Pixee delivers remediation as pull requests, applying deterministic codemods for known vulnerability patterns and AI-powered generation for complex scenarios.

## Finding Types

| Category                  | Examples                              | Fix Mode           |
| ------------------------- | ------------------------------------- | ------------------ |
| Injection vulnerabilities | SQL injection, XSS, command injection | Deterministic      |
| Authentication weaknesses | Insecure session management           | Deterministic + AI |
| Cryptographic issues      | Weak algorithms, hardcoded keys       | Deterministic      |
| Dataflow vulnerabilities  | Taint propagation across functions    | AI                 |

## Setup

1. **Install Pixee** for your platform.
2. **Export Fortify findings as SARIF** — use Fortify's FPR-to-SARIF conversion or export from Fortify Software Security Center (SSC).
3. **Upload SARIF to Pixee** via CI pipeline integration or the Pixee API endpoint.
4. **Pixee triages findings** and opens PRs for remediable issues.
5. **Review and merge.**

**Prerequisites:** Fortify SCA or SSC with findings, SARIF export capability, Pixee platform integration configured.

See [Integrations Overview](/integrations/integrations-overview) for the full scanner coverage matrix.
