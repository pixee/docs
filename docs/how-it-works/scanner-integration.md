---
title: Scanner Integration
slug: /how-it-works/scanner-integration
track: both
content_type: guide
seo_title: "How Scanner Integration Works | 12+ Native Scanners"
description: How Pixee ingests findings from 12 natively integrated scanners and any SARIF-producing tool. Two-tier integration architecture and metadata extraction.
sidebar_position: 5
---

Pixee integrates with 12 natively supported scanners and any SARIF-producing tool through a two-tier architecture. Dedicated handlers extract scanner-specific metadata from tools like CodeQL, Semgrep, and Checkmarx for maximum triage accuracy. Universal SARIF ingestion handles everything else -- including proprietary and internal scanners -- with zero pre-built integration required. Findings from all scanners flow into the same triage and remediation pipeline, so heterogeneous scanner stacks get unified resolution through one platform.

Pixee does not replace your scanners. It sits downstream of them. Your existing SAST tools continue to scan your code exactly as they do today. Pixee consumes each tool's output, triages every finding, and delivers remediation as pull requests for confirmed vulnerabilities.

## Two-Tier Integration Architecture

**Tier 1 -- Native (Dedicated) Handlers.** For the most widely deployed SAST tools, Pixee has dedicated handlers that extract scanner-specific metadata. Each handler understands the idiosyncrasies of that tool's SARIF output -- where rule descriptions live, whether dataflow traces are available, and what metadata the scanner includes or omits. Richer metadata extraction means higher triage accuracy.

**Tier 2 -- Universal SARIF Ingestion.** For any scanner that produces SARIF output (the OASIS open standard for static analysis results), Pixee ingests findings automatically. No pre-built integration required. The system dynamically adapts its handling strategy based on whatever metadata the SARIF contains.

Both tiers feed into the same downstream [triage](/how-it-works/triage-engine) and [remediation](/how-it-works/fix-generation) pipeline. The dedicated handlers provide richer context where available; the universal path ensures nothing is locked out.

## Deep Scanner Integrations

### CodeQL (GitHub Advanced Security)

CodeQL is a deep integration with dedicated SARIF parsing that extracts the full richness of CodeQL output:

- Extracts **codeFlows** -- multi-step source-to-sink dataflow traces that give the triage engine full dataflow context, not just the final finding location
- Handles CodeQL's non-standard SARIF behavior where rule metadata is stored on `tool.extensions` rather than `driver`
- Extracts `help.markdown` from rule metadata for rich vulnerability descriptions
- Pre-configured handlers for common CodeQL rules

CodeQL is commonly used via GitHub Advanced Security. Pixee triages CodeQL findings through the same pipeline as all other scanners.

### Semgrep

Dedicated handler with Semgrep-specific metadata extraction:

- Extracts `fullDescription.text` for rule explanations used in triage context
- Supports both Semgrep OSS and Semgrep Pro rule output

Supports both Semgrep OSS and Semgrep Pro rule output. Findings are classified with structured justification.

### Checkmarx

Dedicated handler with an adaptive strategy for metadata-poor SARIF:

- Compensates for Checkmarx's sparse SARIF output (minimal rule descriptions, no codeFlows)
- Uses a rule-ID-only prompting strategy that routes findings to the adaptive triage pipeline, which re-derives context directly from the codebase
- Includes 3 Checkmarx-specific remediation codemods (SQL parameterization for .NET and JavaScript, NoSQL parameterization for JavaScript)

Checkmarx SARIF exports contain minimal metadata. Pixee's handler compensates for the metadata gap by re-deriving context from the codebase.

## Standard Scanner Integrations

| Scanner                    | Status | Integration Method                                          |
| -------------------------- | ------ | ----------------------------------------------------------- |
| **Veracode**               | GA     | SARIF pipeline with tool-specific identification            |
| **Snyk Code**              | GA     | SARIF pipeline with MagicMod dispatcher support             |
| **SonarQube / SonarCloud** | GA     | SARIF pipeline with dedicated prompt builders               |
| **HCL AppScan**            | GA     | SARIF ingestion pipeline                                    |
| **Polaris (Synopsys)**     | GA     | SARIF ingestion pipeline                                    |
| **GitLab SAST**            | GA     | SARIF pipeline with dedicated namespace                     |
| **Trivy**                  | GA     | SARIF pipeline with MagicMod dispatcher support             |
| **DefectDojo**             | GA     | SARIF pipeline (aggregates findings from multiple scanners) |

All 12 named scanners are GA. See individual scanner integration pages for per-tool setup guides and full capability details.

## Universal SARIF Support

Any scanner that produces SARIF output works with Pixee -- no pre-built integration required.

**SARIF** (Static Analysis Results Interchange Format) is the OASIS open standard for static analysis results. Most modern SAST, SCA, and secret-scanning tools produce SARIF output natively or via converters.

**What this means for your organization:**

- Internal and proprietary scanners that output SARIF work out of the box
- New commercial scanners are supported on day one if they produce SARIF
- You are never locked to a specific tool list
- The system dynamically adapts its handling strategy based on available metadata
- Resilient processing degrades gracefully on malformed or novel tool output

**Key principle:** Bring whatever you have that outputs SARIF. Pixee handles it.

## What Metadata Matters

Triage accuracy scales with the richness of metadata each scanner includes in its SARIF output. Pixee adapts its strategy based on what is available:

| Metadata Type                       | Which Scanners Provide It                              | How Pixee Uses It                                                                                |
| ----------------------------------- | ------------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| **codeFlows** (dataflow paths)      | CodeQL (multi-step source-to-sink)                     | Full dataflow context for triage -- traces from source to sink, not just the final location      |
| **Rule descriptions**               | Semgrep (fullDescription.text), CodeQL (help.markdown) | Enriches triage context with rule semantics and vulnerability explanation                        |
| **Severity ratings**                | Most scanners                                          | Input to context-aware severity adjustment (may be upgraded or downgraded based on code context) |
| **Language tags**                   | Most scanners                                          | Routes to language-specific codemods and analysis strategies                                     |
| **Rule ID only** (minimal metadata) | Checkmarx, some internal tools                         | Triggers adaptive triage that re-derives context from the codebase                               |

Rich-metadata scanners get deep extraction. Sparse-metadata scanners get compensatory strategies. No scanner is left behind.

## Platform Integrations

| Platform         | SARIF Ingestion | Native CodeQL/GHAS | Notes                                        |
| ---------------- | --------------- | ------------------ | -------------------------------------------- |
| **GitHub**       | Full support    | Deep integration   | CodeQL findings via GHAS API or SARIF upload |
| **GitLab**       | Full support    | Via SARIF upload   | GitLab SAST has dedicated namespace          |
| **Azure DevOps** | Full support    | Via SARIF upload   | Standard SARIF pipeline                      |
| **Bitbucket**    | Full support    | Via SARIF upload   | Standard SARIF pipeline                      |

All scanner integrations are available across SaaS and Enterprise Server deployment models.

**[See all integrations](/integrations/overview)** | [Platform architecture](/platform/architecture)

## Frequently Asked Questions

### What scanners does Pixee support?

Pixee natively integrates with 12 scanners: CodeQL, Semgrep, Checkmarx, Veracode, Snyk Code, SonarQube, AppScan, Polaris, GitLab SAST, Trivy, and DefectDojo. Any additional scanner that produces SARIF output works automatically through universal SARIF ingestion -- including proprietary and internal tools.

### Does Pixee support SARIF format?

Yes. Pixee's universal SARIF engine processes any SARIF-conforming output, including from proprietary and internal scanners. No pre-built integration is required. SARIF is the OASIS open standard for static analysis results, and most modern security tools produce it natively or via converters.

### Can I use Pixee with multiple scanners at the same time?

Yes. Findings from all connected scanners flow through the same triage and remediation pipeline.

### Does this lock me into Pixee's ecosystem?

No. Pixee sits downstream of your existing scanners -- it does not replace them. Your detection tools continue running exactly as they do today. Pixee adds triage and remediation on top. If you remove Pixee, your scanners, your code, and all previously merged fixes remain intact. The scanner-agnostic architecture means you can change your detection stack at any time without affecting the resolution layer.
