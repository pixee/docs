---
title: Triage
slug: /platform/triage
track: both
content_type: guide
seo_title: "Automated Vulnerability Triage | Up to 98% False Positive Reduction"
description: How Pixee's three-tier triage engine classifies every vulnerability finding with structured, auditable evidence.
sidebar_position: 3
---

Pixee's triage engine classifies every vulnerability finding as true positive, false positive, or won't-fix through codebase-aware exploitability analysis. The three-tier progressive architecture handles known patterns at sub-second speed, investigates ambiguous cases via AI agents, and generates custom analyzers for novel vulnerability types. The result: up to 98% false positive reduction with structured evidence on every verdict, across findings from natively integrated scanners.

Triage is co-equal with [remediation](/platform/remediation). Together they close the loop from "scanner found something" to "vulnerability is fixed."

## Three-Tier Progressive Architecture

Pixee routes every finding through a tiered system that applies the cheapest sufficient intelligence. Routing is automatic — no configuration required.

| Tier | Strategy | Speed | LLM Cost | Auditability | Coverage |
|---|---|---|---|---|---|
| **Tier 1: Structured** | 15+ deterministic analyzers | Sub-second | Zero | Reproducible — same input, same output | Known vulnerability classes (SQL injection, XSS, command injection, path traversal, 12+ more) |
| **Tier 2: Agentic** | AI agents dynamically search the codebase | Seconds | Per-finding | Readable investigation trail with every search and reasoning step | Ambiguous findings, novel frameworks, custom security controls |
| **Tier 3: Adaptive** | Handles novel rule types automatically, expanding coverage as new rule types are encountered | Minutes (first encounter), faster on subsequent encounters | Per-finding (first encounter only) | Generated analyzer is inspectable | Novel rule types, proprietary scanners, custom rulesets |

**End-to-end flow:**

1. A finding arrives from any SARIF-producing scanner.
2. Tier 1 checks whether a deterministic analyzer exists for this vulnerability class. If yes and confidence is sufficient, triage completes at sub-second speed.
3. If Tier 1 cannot decide, the finding routes to Tier 2. An AI agent investigates the codebase — searching for security controls, tracing dataflow, and building an evidence chain.
4. If Tier 2 cannot resolve the finding (typically because the rule type is novel), Tier 3 handles it automatically and coverage expands for future findings of the same type.
5. Regardless of which tier resolved it, every finding exits with the same structured verdict.

**Cost efficiency:** Most findings resolve at Tier 1, where there is no LLM cost. Only genuinely complex findings incur AI inference cost.

**Expanding coverage:** Pixee handles novel and custom rule types automatically — including proprietary scanners, custom Semgrep rules, and internal CodeQL queries — without manual configuration. Coverage expands as new rule types are encountered.

## Context-Aware Intelligence

A shared intelligence layer enriches all three tiers with codebase context. Reachability analysis alone is not sufficient — reachability tells you whether code can be reached, not whether a vulnerability is actually exploitable.

**Context signals evaluated on every finding:**

**Dataflow quality.** Pixee evaluates the quality and completeness of dataflow evidence available for each finding. Findings with stronger dataflow evidence — where the full taint path from source to sink is traceable — receive higher-confidence verdicts. Findings with limited dataflow evidence are handled conservatively.

**Production vs. test classification.** A SQL injection in a production API endpoint is critical. The same pattern in a test fixture is not. Pixee classifies code context and adjusts severity accordingly, so dashboards reflect real exploit risk rather than raw rule counts.

**Security control detection.** When a sanitizer, validator, or framework-specific protection exists between a source and a sink, the system identifies it and factors it into the verdict. This is the difference between "this function is reachable" and "this function is reachable but the input is sanitized before it arrives."

**Intentionally-vulnerable project filtering.** Demo applications, CTF challenges, and security training repositories generate permanent scanner noise. Pixee detects these projects and filters them from the triage pipeline.

**Severity adjustment.** When context signals indicate real-world risk differs from raw scanner severity, the system adjusts up or down. Every adjustment includes an audit trail.

## Triage Outcomes

Every triage verdict is a structured, machine-processable artifact.

| Status | Meaning | Recommended Action |
|---|---|---|
| **True Positive** | The finding is a real, exploitable vulnerability in this code context | Escalate for remediation — Pixee can generate a fix automatically |
| **False Positive** | The scanner fired on a pattern that is not exploitable in this context | Suppress from developer view; remove from backlog noise |
| **Won't Fix** | Technically real but not worth fixing given the context (test code, acceptable risk, compensating controls) | Deprioritize; document the rationale for auditors |
| **Suspicious** | Insufficient evidence for a definitive verdict | Route to a security engineer for manual assessment |

**What ships with every verdict:**

| Component | What It Contains |
|---|---|
| **Typed status** | True Positive, False Positive, Won't Fix, or Suspicious — not a numeric score |
| **Adjusted severity** | Severity re-ranked based on context signals |
| **Justification prose** | Human-readable explanation of why this verdict was reached |
| **Code snippets** | The sanitizer location, dataflow path, or framework control that drove the decision |
| **Confidence score** | Quantified confidence in the verdict |
| **Investigation trail** (Tier 2/3) | Step-by-step record of agent searches, control checks, and reasoning chain |

**Audit defensibility.** Compliance officers and auditors see exactly why a finding was suppressed. The justification and code snippets provide a defensible record for every triage decision.

**Machine processability.** Typed statuses mean downstream systems can consume verdicts programmatically — dashboards, workflow triggers, SLA tracking, and SIEM integrations all work with structured data rather than freeform text.

**Override capability.** Security engineers can disagree with a verdict and override it, because they can see exactly what evidence the system used. Overrides are recorded and used to improve future classifications for your codebase.

## Scanner-Agnostic Coverage

Triage works across any SARIF-producing scanner. Customers with heterogeneous stacks — multiple commercial scanners plus custom rules — get a single triage layer that handles all of it.

- **Natively integrated scanners** with scanner-specific metadata extraction (CodeQL, SonarQube, Checkmarx, Veracode, Snyk Code, Semgrep, AppScan, Polaris, Fortify, Contrast, GitLab SAST, GitLab SCA, Trivy, and others)
- **Universal SARIF ingestion** for any additional scanner (50+ validated)
- **Custom rule coverage** — proprietary Semgrep rules, internal CodeQL queries, and custom scanner rulesets are handled by Tier 2 and Tier 3 without vendor integration work
- **Cross-tool deduplication** — when multiple scanners flag the same finding, the system eliminates duplicates

The triage layer sits above your existing detection stack. You do not need to change, consolidate, or replace any scanners to use Pixee.
