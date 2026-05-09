---
title: Platform Architecture
slug: /platform/architecture
track: leader
content_type: conceptual
seo_title: "Pixee Platform Architecture | How It All Fits"
description: Three-component architecture with progressive triage, hybrid remediation, and native PR delivery. End-to-end processing flow from scanner finding to merged fix.
sidebar_position: 2
---

Pixee's Agentic Security Engineering Platform uses a three-component architecture — a backend platform, an analysis service, and a user interface — to process vulnerability findings from any scanner through unified triage and remediation pipelines. Findings arrive via webhook or API, pass through a progressive triage engine, and exit as validated pull requests. The system handles everything from sub-second deterministic triage to multi-agent AI fix planning without requiring you to replace any existing tools.

This page walks through the end-to-end processing flow, from scanner finding to merged fix.

## End-to-End Processing Flow

Every vulnerability finding follows the same path through Pixee, regardless of which scanner produced it or which language the code is written in:

| Stage                   | What Happens                                                                 | Output                                                                            |
| ----------------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| **1. Scan Ingestion**   | Finding arrives via webhook or API; normalized into a common internal format | Standardized finding with maximum available metadata                              |
| **2. Triage**           | Three-tier progressive analysis determines exploitability                    | Typed verdict (true positive, false positive, won't fix) with structured evidence |
| **3. Remediation**      | Hybrid engine generates a validated fix for confirmed vulnerabilities        | Code change that passed independent quality evaluation                            |
| **4. PR Delivery**      | Fix shipped as a native pull request on your platform                        | Reviewable diff with vulnerability context, quality scores, and description       |
| **5. Developer Review** | Your team reviews, tests, and merges through existing workflow               | Merged fix or feedback                                                            |

SAST and SCA findings both flow through this same pipeline. There is no separate workflow for dependency vulnerabilities versus first-party code findings.

## Scan Ingestion

Findings arrive from natively integrated scanners or any SARIF-producing tool:

**Native integrations with dedicated handlers:** CodeQL (GitHub Advanced Security), SonarQube/SonarCloud, Checkmarx, Veracode, Snyk Code, Semgrep, AppScan, Polaris, Fortify, Contrast, GitLab SAST, GitLab SCA, Trivy, Arnica, and Datadog SAST.

Each native integration has a tool-specific handler that extracts maximum metadata from the scanner's output format. CodeQL findings include codeFlows and help documentation. Semgrep findings carry full rule descriptions. Metadata-poor tools like Checkmarx use rule-ID-based strategies to compensate for sparse SARIF output.

**Universal SARIF fallback:** Any scanner that produces SARIF output works through tool-agnostic processing. Over 50 scanner tools have been validated via this path. No scanner is locked out of the pipeline.

All findings are normalized into a common internal format before downstream processing. This normalization is what makes the triage and remediation engines scanner-agnostic -- they operate on standardized findings, not raw scanner output.

## Triage Engine

The triage engine classifies every finding through a three-tier progressive architecture. Each tier represents a different analysis strategy, and the system routes each finding to the cheapest sufficient tier automatically.

| Tier                   | Strategy                                                                                     | Speed                     | LLM Cost    | Best For                                                               |
| ---------------------- | -------------------------------------------------------------------------------------------- | ------------------------- | ----------- | ---------------------------------------------------------------------- |
| **Tier 1: Structured** | 15+ deterministic analyzers                                                                  | Sub-second                | Zero        | Known patterns (SQL injection, XSS, command injection, path traversal) |
| **Tier 2: Agentic**    | AI agents dynamically search the codebase                                                    | Seconds                   | Per-finding | Ambiguous findings, novel frameworks, custom security controls         |
| **Tier 3: Adaptive**   | Handles novel rule types automatically, expanding coverage as new rule types are encountered | Minutes (first encounter) | Per-finding | Novel rule types, proprietary scanners, custom rulesets                |

**Progressive fallback:** The system attempts Tier 1 first. If the deterministic analyzer cannot reach a high-confidence verdict, the finding escalates to Tier 2. If the agentic investigation cannot resolve it, Tier 3 handles it automatically and coverage expands for future findings of the same type. Most findings resolve at Tier 1.

A shared context-aware intelligence layer enriches every tier with codebase signals: dataflow quality, production versus test classification, security control detection, and intentionally-vulnerable project filtering. Every verdict includes a typed status, adjusted severity, justification with code snippets, and a confidence score.

For false positive reduction data, see [Triage Capabilities](/platform/triage).

For full triage details, see [Triage](/platform/triage).

## Remediation Engine

The remediation engine uses a hybrid-intelligence model: deterministic codemods handle known vulnerability patterns, and AI-powered fixes handle everything else.

**Deterministic codemods:** Pre-built, rule-based transformations for known OWASP/SANS security patterns. Same input, same output, every time. Zero LLM involvement. Zero hallucination risk. Open-source engines (codemodder-java, codemodder-python) are publicly inspectable. See [Remediation](/platform/remediation) for the full codemod library.

**AI-powered fixes:** Handle custom frameworks, multi-file dataflow vulnerabilities, and novel patterns where deterministic rules cannot reach. Pixee extracts maximum metadata from each scanner's native output format, normalizing findings so the AI receives the right context regardless of source scanner.

**Multi-agent fix planning:** Complex fixes that span dependency manifests, source files, and configuration changes are planned before execution. Specialized agents handle version decisions, source file identification, and manifest updates independently. Plans are evaluated for quality before code changes begin.

**Independent fix evaluation:** Every generated fix passes through a separate quality gate scoring Safety (no breaking changes), Effectiveness (resolves the vulnerability), and Cleanliness (code quality). The evaluator runs as a separate inference call -- the generator does not grade its own work. Fixes that fail evaluation are retried with structured feedback or suppressed entirely.

For merge rate data and trust details, see [Security & Trust](/platform/security).

For full remediation details, see [Remediation](/platform/remediation).

## PR Delivery

Validated fixes are delivered as native pull requests on GitHub, GitLab, Azure DevOps, or Bitbucket. PR-only delivery is a non-negotiable architectural constraint -- there is no mode, setting, or override that allows direct commits.

Every PR includes:

- **Full diff** showing exactly what changed
- **Vulnerability context** explaining what the scanner found and why the fix addresses it
- **Quality scores** from the independent fix evaluation
- **Detailed description** with remediation rationale

Your existing code review policies, CI/CD pipelines, SAST re-scanning, and branch protection rules all apply to Pixee changes exactly as they apply to human-written code. The same SAST tools that found the original vulnerability also scan the proposed fix.

Standard `git revert` applies if any merged change needs to be undone. There is no runtime dependency on Pixee for merged code -- removing Pixee leaves all previously merged fixes intact as standard code.

## LLM Orchestration

Pixee uses hierarchical model routing to assign the right AI capability to each task. Fast triage queries use lightweight models. Deep reasoning tasks use more capable models. Code generation uses models optimized for that purpose.

The platform supports multiple LLM provider families:

| Provider Family                 | Deployment Context                     |
| ------------------------------- | -------------------------------------- |
| OpenAI                          | Cloud deployments                      |
| Azure OpenAI / Azure AI Foundry | Enterprise cloud with Azure compliance |
| Anthropic Claude                | Cloud deployments                      |
| Azure Anthropic                 | Enterprise cloud with Azure compliance |
| Any OpenAI-compatible endpoint  | Custom or self-hosted LLM deployments  |

Customers choose providers based on compliance requirements, cost preferences, or performance needs. Bring Your Own Model (BYOM) support means enterprises deploy the LLM provider that satisfies their AI governance policies.

For air-gapped deployments, a customer-hosted LLM is required. No code leaves the customer's environment. The only outbound connection is license validation, which can be proxied.

## Three-Component Stack

| Component            | Responsibility                                                                               |
| -------------------- | -------------------------------------------------------------------------------------------- |
| **Backend Platform** | Platform orchestration, scan ingestion, PR authoring, API layer, webhook processing          |
| **Analysis Service** | Triage analysis, remediation generation, fix evaluation, SCA processing, code transformation |
| **User Interface**   | Dashboard, findings management, configuration, reporting                                     |

The Analysis Service handles the computationally intensive work -- triage decisions, fix generation, and quality evaluation. The Backend Platform manages the integration surface: scanner webhooks, SCM platform APIs, and PR lifecycle. The User Interface provides visibility into triage outcomes, remediation activity, and configuration.
