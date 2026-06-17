---
title: What is Agentic Security Engineering?
slug: /platform/what-is-agentic-security-engineering
track: leader
content_type: conceptual
seo_title: "What is Agentic Security Engineering? | Pixee"
description: Agentic security engineering uses purpose-built AI agents to triage and remediate application security vulnerabilities. Definition, architecture, and processing flow.
sidebar_position: 1
---

Agentic security engineering is a discipline where purpose-built AI agents autonomously triage and remediate application security vulnerabilities across the full development lifecycle. Pixee sits downstream of your existing scanners — receiving findings via webhook or API, determining which are exploitable, generating validated fixes, and delivering them as pull requests.

## The Four-Layer Security Stack

Pixee adds triage, remediation, and delivery layers on top of your existing detection tools:

| Layer              | Function                                  | Who Provides It                                                                      |
| ------------------ | ----------------------------------------- | ------------------------------------------------------------------------------------ |
| **1. Detection**   | Find vulnerabilities                      | Your existing scanners (SonarQube, Checkmarx, Semgrep, CodeQL, Snyk, Veracode, etc.) |
| **2. Triage**      | Determine which findings are real threats | Pixee — see [Triage](/platform/triage)                                               |
| **3. Remediation** | Generate validated code fixes             | Pixee — deterministic + AI hybrid. See [Remediation](/platform/remediation)          |
| **4. Delivery**    | Ship fixes through existing workflow      | Pixee — PRs in GitHub, GitLab, ADO, Bitbucket                                        |

Pixee integrates natively with a growing list of scanners and accepts any SARIF-producing tool. No changes to your detection stack are required.

## Two Co-Equal Capabilities

### Triage Automation

Every scanner finding passes through exploitability analysis that goes beyond basic pattern matching. The triage engine classifies each finding as TRUE_POSITIVE, FALSE_POSITIVE, or WONT_FIX. Every classification includes a structured justification — the specific code paths, security controls, or context that drove the decision. This is not a confidence score. It is an auditable investigation trail.

Up to 98% false positive reduction. See [Triage](/platform/triage) for the full architecture.

### Remediation Automation

For confirmed vulnerabilities, the platform generates context-aware code fixes:

- **Deterministic codemods:** Pre-built, rule-based transformations for known vulnerability patterns. Same input, same output, every time. Zero LLM involvement. Zero hallucination risk.
- **AI-powered fixes:** For novel or complex patterns where deterministic rules cannot reach, constrained AI generates fixes that are independently evaluated for Safety, Effectiveness, and Cleanliness before any developer sees them.
- **Pull request delivery:** Every fix ships as a standard PR in GitHub, GitLab, Azure DevOps, or Bitbucket. Never a direct commit.

76% merge rate on production deployments. See [Remediation](/platform/remediation) and [Security & Trust](/platform/security) for details.

## What Makes It "Agentic"

The term "agentic" distinguishes this approach from both rule-based automation and general-purpose AI coding tools:

**Purpose-built agents, not general-purpose assistants.** These agents are built for security vulnerability analysis. They do not write features, generate business logic, or perform open-ended code completion. Their scope is narrow: SAST-identified security issues, typically 1-5 lines of code applying OWASP/SANS established patterns.

**Reasoning-and-acting loop.** Agents observe a finding, select an investigative tool (code search, call-graph traversal, security-control detection), execute it, evaluate the result, and iterate until they have sufficient evidence to make a classification. This is a dynamic investigation, not a single-pass classification.

**Multi-agent orchestration.** Specialized agents handle distinct tasks independently: triage analysis, fix planning, dependency resolution, and fix quality evaluation. The agent that generates a fix is not the agent that evaluates it — preventing self-grading.

**Hybrid intelligence architecture.** The system routes each task to the cheapest sufficient method. Known patterns get deterministic rules (sub-second, zero cost). Complex patterns get AI investigation. Novel and custom rule types — including proprietary scanners and custom rulesets — are handled automatically, with coverage expanding as new rule types are encountered. Routing is automatic.

## End-to-End Processing Flow

| Stage                   | What Happens                                                                 | Output                                                                            |
| ----------------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| **1. Scan Ingestion**   | Finding arrives via webhook or API; normalized into a common internal format | Standardized finding with maximum available metadata                              |
| **2. Triage**           | Three-tier progressive analysis determines exploitability                    | Typed verdict (true positive, false positive, won't fix) with structured evidence |
| **3. Remediation**      | Hybrid engine generates a validated fix for confirmed vulnerabilities        | Code change that passed independent quality evaluation                            |
| **4. PR Delivery**      | Fix shipped as a native pull request on your platform                        | Reviewable diff with vulnerability context, quality scores, and description       |
| **5. Developer Review** | Your team reviews, tests, and merges through existing workflow               | Merged fix or feedback                                                            |

SAST and SCA findings both flow through this same pipeline.

## Technical Stack

| Component            | Responsibility                                                                               |
| -------------------- | -------------------------------------------------------------------------------------------- |
| **Backend Platform** | Platform orchestration, scan ingestion, PR authoring, API layer, webhook processing          |
| **Analysis Service** | Triage analysis, remediation generation, fix evaluation, SCA processing, code transformation |
| **User Interface**   | Dashboard, findings management, configuration, reporting                                     |

See [Platform Architecture](/platform/architecture) for the full technical stack and LLM orchestration details.
