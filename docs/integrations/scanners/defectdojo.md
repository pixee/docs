---
title: DefectDojo Integration
slug: /integrations/scanners/defectdojo
track: both
content_type: guide
seo_title: DefectDojo Integration with Pixee
description: Pixee integration with DefectDojo for automated triage and remediation of aggregated findings from multiple scanners.
sidebar_position: 5
---

# DefectDojo Integration

Pixee integrates with DefectDojo to triage aggregated findings and deliver remediation as pull requests. DefectDojo serves as the management layer — organizing and tracking findings — but does not triage for exploitability or generate code fixes. Pixee adds those two capabilities. Your DefectDojo instance continues operating as your centralized vulnerability tracker; Pixee acts on what DefectDojo organizes.

DefectDojo is an open-source application vulnerability management platform that consolidates findings from multiple scanners.

## What DefectDojo Does

- **Aggregates findings** from multiple security scanners into a single view
- **Deduplicates findings** across tools and scan runs
- **Tracks vulnerability lifecycle** (open, verified, mitigated, closed)
- **Provides vulnerability metrics** and reporting
- **Supports import from 150+ scanner formats**

## How Pixee Enhances DefectDojo

### Triage

DefectDojo aggregates findings from multiple scanners, but triaging is still manual — security teams review each finding to determine whether it is a real threat. Pixee automates this step with exploitability analysis, classifying each finding as TRUE_POSITIVE, FALSE_POSITIVE, or WONT_FIX with structured evidence.

### Remediation

DefectDojo tracks vulnerability status but does not generate code fixes. Pixee delivers fixes as pull requests for confirmed vulnerabilities, moving findings from "open" to "mitigated" with actual code changes.

## Finding Types

| Category                   | Examples                    | Fix Mode                      |
| -------------------------- | --------------------------- | ----------------------------- |
| SAST findings (aggregated) | Injection, XSS, auth issues | Deterministic + AI            |
| SCA findings (aggregated)  | Dependency CVEs             | Deterministic (version bumps) |
| Custom scanner findings    | Organization-specific rules | AI                            |

## Setup

1. **Install Pixee** for your platform.
2. **Configure DefectDojo export** — export findings in SARIF format from DefectDojo.
3. **Connect to Pixee** — upload SARIF findings via Pixee's integration endpoint or configure automated export.
4. **Review and merge** — Pixee triages findings and opens PRs for remediable issues.

**Prerequisites:** DefectDojo instance with findings imported, Pixee platform integration configured.

## FAQ

### Does Pixee replace DefectDojo?

No. DefectDojo is a vulnerability management platform that tracks and organizes findings. Pixee is a resolution platform that triages and fixes them. They serve different functions and work together.

### How do findings flow between DefectDojo and Pixee?

Findings are exported from DefectDojo in SARIF format and ingested by Pixee for triage and remediation. When Pixee generates a fix, the resulting PR can be tracked back in DefectDojo as a mitigation action.

### Can Pixee update DefectDojo finding status automatically?

Integration capabilities between Pixee and DefectDojo depend on your deployment configuration. Contact the Pixee team for current webhook and API integration options.

See [Integrations Overview](/integrations/overview) for the full scanner coverage matrix.
