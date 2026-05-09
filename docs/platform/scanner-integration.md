---
title: Scanner Integration
slug: /platform/scanner-integration
track: both
content_type: guide
seo_title: "Scanner Integration | Native Scanners + Universal SARIF"
description: How Pixee integrates with natively supported scanners and any SARIF-producing tool. Two-tier integration architecture and metadata extraction.
sidebar_position: 7
---

Pixee integrates with a growing list of natively supported scanners and any SARIF-producing tool through a two-tier architecture. Dedicated handlers extract scanner-specific metadata from tools like CodeQL, Semgrep, and Checkmarx for maximum triage accuracy. Universal SARIF ingestion handles everything else — including proprietary and internal scanners — with zero pre-built integration required.

Pixee does not replace your scanners. It sits downstream of them. Your existing SAST tools continue to scan your code exactly as they do today. Pixee consumes each tool's output, triages every finding, and delivers remediation as pull requests for confirmed vulnerabilities.

## Two-Tier Integration Architecture

**Tier 1 — Native (Dedicated) Handlers.** For the most widely deployed SAST tools, Pixee has dedicated handlers that extract scanner-specific metadata. Each handler understands the idiosyncrasies of that tool's SARIF output — where rule descriptions live, whether dataflow traces are available, and what metadata the scanner includes or omits. Richer metadata extraction means higher triage accuracy.

**Tier 2 — Universal SARIF Ingestion.** For any scanner that produces SARIF output (the OASIS open standard for static analysis results), Pixee ingests findings automatically. No pre-built integration required. The system dynamically adapts its handling strategy based on whatever metadata the SARIF contains.

Both tiers feed into the same downstream [triage](/platform/triage) and [remediation](/platform/remediation) pipeline.

## Deep Scanner Integrations

### CodeQL (GitHub Advanced Security)

- Extracts **codeFlows** — multi-step source-to-sink dataflow traces that give the triage engine full dataflow context
- Handles CodeQL's non-standard SARIF behavior where rule metadata is stored on `tool.extensions` rather than `driver`
- Extracts `help.markdown` from rule metadata for rich vulnerability descriptions
- Pre-configured handlers for common CodeQL rules

### Semgrep

- Extracts `fullDescription.text` for rule explanations used in triage context
- Supports both Semgrep OSS and Semgrep Pro rule output

### Checkmarx

- Compensates for Checkmarx's sparse SARIF output (minimal rule descriptions, no codeFlows)
- Uses compensatory strategies that re-derive triage context directly from the codebase when scanner metadata is sparse
- Includes Checkmarx-specific remediation codemods (SQL parameterization for .NET and JavaScript, NoSQL parameterization for JavaScript)

## Standard Scanner Integrations

| Scanner | Status | Integration Method |
|---|---|---|
| **Veracode** | GA | SARIF pipeline with tool-specific identification |
| **Snyk Code** | GA | SARIF pipeline with native metadata extraction |
| **SonarQube / SonarCloud** | GA | SARIF pipeline with native metadata extraction |
| **HCL AppScan** | GA | SARIF ingestion pipeline |
| **Polaris (Synopsys)** | GA | SARIF ingestion pipeline |
| **Fortify** | GA | SARIF ingestion pipeline |
| **Contrast** | GA | SARIF ingestion pipeline |
| **GitLab SAST** | GA | SARIF pipeline with dedicated namespace |
| **GitLab SCA** | GA | SARIF pipeline |
| **Trivy** | GA | SARIF pipeline with native metadata extraction |
| **DefectDojo** | GA | SARIF pipeline (aggregates findings from multiple scanners) |

All named scanner integrations are GA. See individual scanner integration pages under [Integrations](/integrations/overview) for per-tool setup guides.

## Universal SARIF Support

Any scanner that produces SARIF output works with Pixee — no pre-built integration required.

**SARIF** (Static Analysis Results Interchange Format) is the OASIS open standard for static analysis results. Most modern SAST, SCA, and secret-scanning tools produce SARIF output natively or via converters.

- Internal and proprietary scanners that output SARIF work out of the box
- New commercial scanners are supported on day one if they produce SARIF
- The system dynamically adapts its handling strategy based on available metadata
- Resilient processing degrades gracefully on malformed or novel tool output

Over 50 scanner tools have been validated via this path.

## What Metadata Matters

Triage accuracy scales with the richness of metadata each scanner includes in its SARIF output.

| Metadata Type | Which Scanners Provide It | How Pixee Uses It |
|---|---|---|
| **codeFlows** (dataflow paths) | CodeQL (multi-step source-to-sink) | Full dataflow context for triage |
| **Rule descriptions** | Semgrep (fullDescription.text), CodeQL (help.markdown) | Enriches triage context with rule semantics |
| **Severity ratings** | Most scanners | Input to context-aware severity adjustment |
| **Language tags** | Most scanners | Routes to language-specific codemods and analysis strategies |
| **Rule ID only** (minimal metadata) | Checkmarx, some internal tools | Triggers compensatory strategies that re-derive context from the codebase |

Rich-metadata scanners get deep extraction. Sparse-metadata scanners get compensatory strategies. No scanner is left behind.

## Platform Integrations

| Platform | SARIF Ingestion | Native CodeQL/GHAS | Notes |
|---|---|---|---|
| **GitHub** | Full support | Deep integration | CodeQL findings via GHAS API or SARIF upload |
| **GitLab** | Full support | Via SARIF upload | GitLab SAST has dedicated namespace |
| **Azure DevOps** | Full support | Via SARIF upload | Standard SARIF pipeline |
| **Bitbucket** | Full support | Via SARIF upload | Standard SARIF pipeline |

All scanner integrations are available across SaaS and Enterprise deployment models.
