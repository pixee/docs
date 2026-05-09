---
title: Universal SARIF Integration
slug: /integrations/sarif-universal
track: both
content_type: guide
seo_title: Universal SARIF Integration with Pixee
description: Connect any SARIF-producing scanner to Pixee for automated triage and remediation. Covers SARIF format requirements and upload methods.
sidebar_position: 2
---

# Universal SARIF Integration

Pixee's Universal SARIF integration accepts findings from any security scanner that produces SARIF output. This means you are not limited to Pixee's natively integrated scanners — if your tool can export SARIF, Pixee can triage and remediate its findings. Universal SARIF is how Pixee stays scanner-agnostic: your choice of detection tools is independent of your choice of resolution platform.

This page covers the SARIF format requirements, upload methods, what metadata Pixee extracts, and the differences between Universal SARIF and native integrations.

## When to Use Universal SARIF

Use Universal SARIF when:

- Your scanner is not in Pixee's [native integration list](/integrations/overview)
- You use a proprietary or custom-built scanner
- You aggregate findings from multiple tools through a central platform that exports SARIF
- You want to evaluate Pixee with a scanner before requesting a native integration

Use a native integration when available — native integrations extract richer metadata and provide deeper triage context than Universal SARIF.

## SARIF Requirements

Pixee supports SARIF version 2.1.0. At minimum, each finding must include a `ruleId`, `message.text`, and a `physicalLocation` (file path and line number). Richer SARIF — particularly `codeFlows` with `threadFlows` — directly improves triage accuracy and fix quality.

For the complete field reference, required vs. optional field breakdown, dataflow quality tiers, and validation guidance, see the [SARIF Reference](/api/sarif).

## Upload Methods

### CI/CD Pipeline Upload

Upload SARIF as a step in your CI/CD pipeline after your scanner runs:

```yaml
# Example: GitHub Actions
- name: Upload SARIF to Pixee
  run: |
    curl -X POST \
      -H "Authorization: Bearer $PIXEE_TOKEN" \
      -H "Content-Type: application/sarif+json" \
      -d @results.sarif \
      https://api.pixee.ai/v1/sarif/upload
```

### Platform-Native Upload

If your scanner integrates with GitHub Code Scanning, GitLab Security Dashboard, or Azure DevOps, Pixee can ingest SARIF through the platform's native security findings API.

### Manual Upload

For evaluation or one-time use, upload SARIF files through the Pixee dashboard.

## What Pixee Extracts from SARIF

| SARIF Element                | What Pixee Does With It                                    |
| ---------------------------- | ---------------------------------------------------------- |
| `ruleId`                     | Maps to known vulnerability patterns for codemod selection |
| `message.text`               | Provides context for AI-powered triage and fix generation  |
| `physicalLocation`           | Identifies the file and line to analyze and fix            |
| `codeFlows`                  | Enables source-to-sink exploitability analysis             |
| `level` (error/warning/note) | Informs triage prioritization                              |
| `rules[].help`               | Provides vulnerability description for fix context         |
| `properties`                 | Custom metadata (e.g., CWE, CVSS) for enriched triage      |

## Native vs. Universal SARIF

| Dimension           | Native Integration                                      | Universal SARIF                                       |
| ------------------- | ------------------------------------------------------- | ----------------------------------------------------- |
| Metadata extraction | Scanner-specific handler extracts maximum context       | Relies on what SARIF contains                         |
| Triage depth        | Full exploitability analysis with scanner-aware context | Exploitability analysis with available SARIF metadata |
| Fix coverage        | Scanner-specific codemod dispatchers                    | Generic codemod matching by rule ID and CWE           |
| Setup               | One-click via platform integration                      | SARIF upload configuration required                   |
| Maintenance         | Pixee maintains handler compatibility                   | You maintain SARIF export compatibility               |

**Recommendation:** Use native integrations when available. Use Universal SARIF for scanners without native support or for evaluation.

## Supported SARIF Producers

Any scanner producing valid SARIF output works with Universal SARIF. Scanners known to produce compatible output include:

- ESLint (with SARIF formatter)
- Psalm
- PHPStan
- Bandit (Python)
- Gosec (Go)
- Brakeman (Ruby)
- Custom scanners with SARIF export
- Security platforms with SARIF aggregation (DefectDojo, GitHub Code Scanning, etc.)

