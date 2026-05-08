---
title: Universal SARIF Integration
slug: /integrations/sarif-universal
track: both
content_type: guide
seo_title: Universal SARIF Integration with Pixee
description: Connect any SARIF-producing scanner to Pixee for automated triage and remediation. Covers SARIF 2.1.0 requirements and upload methods.
sidebar_position: 2
---

# Universal SARIF Integration

Pixee's Universal SARIF integration accepts findings from any security scanner that produces SARIF 2.1.0 output. This means you are not limited to Pixee's 12 natively integrated scanners — if your tool can export SARIF, Pixee can triage and remediate its findings. Universal SARIF is how Pixee stays scanner-agnostic: your choice of detection tools is independent of your choice of resolution platform.

This page covers the SARIF format requirements, upload methods, what metadata Pixee extracts, and the differences between Universal SARIF and native integrations.

## When to Use Universal SARIF

Use Universal SARIF when:

- Your scanner is not in Pixee's [native integration list](/integrations/overview)
- You use a proprietary or custom-built scanner
- You aggregate findings from multiple tools through a central platform that exports SARIF
- You want to evaluate Pixee with a scanner before requesting a native integration

Use a native integration when available — native integrations extract richer metadata and provide deeper triage context than Universal SARIF.

## SARIF 2.1.0 Requirements

Pixee supports SARIF version 2.1.0 (the OASIS standard). Your SARIF file must include:

### Required Fields

| Field          | Path                                     | Description                            |
| -------------- | ---------------------------------------- | -------------------------------------- |
| Schema version | `$schema`                                | Must reference SARIF 2.1.0 schema      |
| Tool info      | `runs[].tool.driver.name`                | Scanner name                           |
| Results        | `runs[].results[]`                       | Array of findings                      |
| Rule ID        | `results[].ruleId`                       | Unique identifier for the finding type |
| Message        | `results[].message.text`                 | Human-readable finding description     |
| Location       | `results[].locations[].physicalLocation` | File path and line number              |

### Optional But Recommended

| Field           | Path                              | Impact on Pixee                                   |
| --------------- | --------------------------------- | ------------------------------------------------- |
| Rule metadata   | `runs[].tool.driver.rules[]`      | Enables richer triage justifications              |
| Code flows      | `results[].codeFlows[]`           | Enables source-to-sink dataflow triage            |
| Severity        | `results[].level`                 | Informs triage prioritization                     |
| Help text       | `runs[].tool.driver.rules[].help` | Provides vulnerability context for fix generation |
| Tags/properties | `results[].properties`            | Custom metadata for organization-specific context |

The more metadata your SARIF contains, the better Pixee's triage and remediation quality. Scanners that produce minimal SARIF (rule ID + location only) still work, but triage justifications are less detailed.

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

Any scanner producing valid SARIF 2.1.0 output works with Universal SARIF. Scanners known to produce compatible output include:

- ESLint (with SARIF formatter)
- Psalm
- PHPStan
- Bandit (Python)
- Gosec (Go)
- Brakeman (Ruby)
- Custom scanners with SARIF export
- Security platforms with SARIF aggregation (DefectDojo, GitHub Code Scanning, etc.)

## Frequently Asked Questions

### Can I use any scanner with Pixee?

Yes, if the scanner produces SARIF 2.1.0 output. Universal SARIF is Pixee's fallback integration that accepts findings from any SARIF-compatible tool. Pixee also has 12 native integrations that provide deeper triage context.

### What if my scanner does not produce SARIF?

Some scanners can be configured to output SARIF via plugins or converters. Check your scanner's documentation for SARIF export options. If SARIF export is not available, contact the Pixee team to discuss custom integration options.

### Is Universal SARIF less accurate than native integrations?

Triage and fix quality depend on the metadata available in the SARIF file. Native integrations use scanner-specific handlers that extract maximum context. Universal SARIF works with whatever metadata the SARIF contains. If your SARIF includes code flows, rule metadata, and help text, the quality difference is minimal.

### How do I validate my SARIF file before uploading?

Use a SARIF validator (the SARIF SDK includes validation tools) to verify your file conforms to the 2.1.0 specification before uploading. Common issues include missing required fields, incorrect schema references, and unsupported SARIF versions.
