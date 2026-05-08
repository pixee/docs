---
title: Polaris Integration
slug: /integrations/scanners/polaris
track: both
content_type: guide
seo_title: Polaris (Synopsys / Black Duck Coverity) Integration with Pixee
description: Pixee integration with Polaris (Synopsys / Black Duck Coverity) for automated triage and remediation of dataflow and code-quality findings.
sidebar_position: 9
---

# Polaris Integration

Pixee integrates with Polaris to triage findings from the Coverity SAST engine and deliver remediation as pull requests. Polaris's strength is thorough, conservative dataflow analysis; that thoroughness produces high finding volumes that mix security vulnerabilities, code quality, and lower-severity patterns. Pixee classifies each finding by exploitability and generates code fixes Polaris does not produce. Your Polaris scans continue running as configured.

> Polaris is the unified application security platform from Synopsys / Black Duck. Note: Synopsys divested its Software Integrity Group, which now operates under the Black Duck Software brand. Polaris remains the unified platform name; Coverity remains the SAST engine name. Pixee works with Polaris regardless of the branding on your license.

## What Polaris Detects

- **SAST via the Coverity engine** — deep dataflow analysis, buffer overflows, injection flaws, concurrency issues, and taint tracking across multiple languages
- **SCA via Black Duck** — open-source license compliance and vulnerability detection
- **Rapid Scan** — lightweight SAST designed for CI/CD integration (faster analysis with narrower rule coverage than full Coverity)
- **API security issues**
- **Infrastructure misconfigurations**

## How Pixee Enhances Polaris

### Triage

The Coverity engine is known for thorough, conservative analysis. This thoroughness produces high volumes of findings that mix security vulnerabilities, code quality issues, and lower-severity patterns. Pixee's triage pipeline classifies each finding as TRUE_POSITIVE, FALSE_POSITIVE, or WONT_FIX with a code-level justification, accounting for framework protections, sanitization logic, and deployment context that Coverity's conservative analysis may not resolve.

### Remediation

Polaris provides findings and remediation guidance but does not generate automated code fixes or pull requests. Pixee closes this gap. True positive findings are automatically fixed using deterministic codemods and AI-powered MagicMods. Fixes are delivered as pull requests matching the team's code conventions.

For the full list of vulnerability types Pixee triages and fixes, see [What Pixee Fixes](/platform/what-pixee-fixes).

## Setup

1. **Run Polaris** on your repository (via Polaris CLI or CI/CD integration).
2. **Export results in SARIF format** from Polaris.
3. **Upload SARIF to Pixee** via API, UI, or CI integration.
4. **Pixee processes findings** through the triage and remediation pipeline.
5. **Review and merge** Pixee-generated PRs.

**Prerequisites:** Polaris account with Coverity SAST scan results, Pixee account with connected repository.

## Common False Positive Patterns Pixee Eliminates

- **Conservative analysis flagging unlikely conditions:** Coverity flags potential issues even when exploitation requires multiple unlikely conditions to align
- **Code quality findings mixed with security:** Polaris reports reliability bugs, code quality issues, and security vulnerabilities in the same output; Pixee separates security from non-security
- **Buffer overflow false positives in managed languages:** Coverity rules designed for C/C++ may produce findings in managed-language code (Java, C#) where memory management is handled by the runtime
- **Test and example code at production severity:** Findings in non-production code flagged at production severity levels

See [Integrations Overview](/integrations/overview) for the full scanner coverage matrix.
