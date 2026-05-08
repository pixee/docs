---
title: Triage Engine
slug: /how-it-works/triage-engine
track: both
content_type: guide
seo_title: "How the Triage Engine Works | Pixee Technical Guide"
description: "Three-tier progressive triage architecture: deterministic analysis, agentic investigation, and adaptive analyzer generation."
sidebar_position: 1
---

Pixee's triage engine routes every vulnerability finding through a three-tier progressive architecture that applies the cheapest sufficient intelligence to each finding. Tier 1 uses 15+ deterministic analyzers for sub-second verdicts with zero LLM cost. Tier 2 deploys AI agents that dynamically investigate the codebase. Tier 3 generates custom analyzers on the fly for novel vulnerability types and caches them for reuse. The result: up to 95% false positive reduction with structured, auditable evidence on every verdict.

Triage is one of two co-equal capabilities in Pixee's Agentic Security Engineering Platform. The other is [Remediation Automation](/how-it-works/fix-generation), which generates validated code fixes for confirmed vulnerabilities. Together they close the loop from "scanner found something" to "vulnerability is fixed."

## How Triage Works End to End

Every finding follows the same pipeline regardless of which scanner produced it. The system routes automatically based on finding characteristics and confidence signals -- no customer configuration required.

**Progressive fallback flow:**

1. **Finding arrives** from any SARIF-producing scanner via one of 12 native scanner integrations
2. **Tier 1 attempt** -- the system checks for a matching deterministic analyzer. If one exists and reaches a high-confidence verdict, triage completes in sub-second time
3. **Tier 2 escalation** -- if Tier 1 lacks a matching analyzer or yields insufficient confidence, the finding routes to AI-powered investigation
4. **Tier 3 escalation** -- if agentic investigation cannot resolve the finding (typically a novel rule type), the adaptive tier generates a custom analyzer on the fly
5. **Structured verdict** -- regardless of which tier resolved it, every finding exits with the same outcome format: typed status, adjusted severity, justification, code evidence, and confidence score

A single pipeline handles findings from all SARIF-producing scanners. A [context-aware intelligence layer](/how-it-works/context-intelligence) enriches every tier with dataflow quality assessment, production vs. test classification, and security control detection.

## Tier 1 -- Deterministic Analysis

Tier 1 runs 15+ structured analyzers for common vulnerability classes. These produce sub-second, reproducible verdicts without invoking an LLM.

**Vulnerability classes covered:** SQL injection, XSS, command injection, path traversal, and 12+ additional common SAST vulnerability types. Each has a dedicated analyzer with class-specific logic.

**Why deterministic matters:**

- **Sub-second latency.** No LLM call means no inference cost and no wait. This is the fastest path through the system.
- **Reproducible.** Same input always produces the same output. Compliance teams and auditors require deterministic, auditable results -- Tier 1 delivers exactly that.
- **High-confidence patterns only.** Tier 1 handles the vulnerability classes where deterministic analysis is reliable. These common patterns make up the bulk of scanner noise. When a pattern is ambiguous, the finding falls through to Tier 2.

Most findings resolve at Tier 1. This means the majority of triage volume incurs zero LLM cost and completes in under one second.

## Tier 2 -- Agentic Investigation

When deterministic rules cannot reach a high-confidence verdict, an AI agent dynamically investigates the finding. This happens with novel frameworks, custom security controls, or context-dependent patterns that do not match a known template.

**How it works:** The agent runs a reasoning-and-acting loop -- observe the finding, select an investigative tool (code search, dataflow tracing, security-control detection), execute it, evaluate the result, and iterate until sufficient evidence exists to emit a verdict.

**What it adds over Tier 1:**

- **Dynamic investigation.** Instead of matching against pre-built patterns, the agent explores the codebase the way a senior security engineer would -- following dataflow, checking for sanitizers, verifying framework protections.
- **Readable investigation trail.** The agent produces a step-by-step reasoning trace: "Searched for the sanitizer, found it on line X, it validates input type Y, therefore this is a false positive." This trail is the artifact that makes triage auditable and defensible.
- **No pre-configuration required.** The agentic tier adapts to whatever codebase it encounters. No per-framework setup, no rule tuning, no onboarding configuration.

Every Tier 2 verdict includes the full investigation trail -- every code search, every control check, and the reasoning chain that led to the conclusion.

## Tier 3 -- Adaptive Analysis

Tier 3 handles the long tail: vulnerability types the system has never encountered before. When a finding reaches Tier 3, the system generates a custom triage analyzer on the fly, then caches it so subsequent findings with the same rule skip the generation step.

**When it kicks in:** Proprietary SAST tools, custom Semgrep rules, internal CodeQL queries, or niche scanners that produce rules outside of standard vulnerability taxonomies.

**How it works:** A multi-stage workflow analyzes the unknown rule's semantics and the finding's context, generates a custom triage analyzer tailored to that specific rule type, runs the generated analyzer against the finding, emits a verdict with justification, and caches the analyzer for future reuse.

**Why this matters:**

- **Self-extending.** Every novel rule type the system encounters becomes a cached analyzer. Coverage grows automatically as customers connect new scanners.
- **Zero manual configuration.** Customers running heterogeneous scanner stacks (CodeQL + Semgrep + internal custom rules) get triage coverage across all of them without requesting vendor integrations.
- **Handles the true long tail.** While Tier 1 covers common patterns and Tier 2 investigates ambiguous cases, Tier 3 handles the genuinely novel.

## Comparing the Three Tiers

| Dimension         | Tier 1: Deterministic             | Tier 2: Agentic                 | Tier 3: Adaptive                                    |
| ----------------- | --------------------------------- | ------------------------------- | --------------------------------------------------- |
| **Speed**         | Sub-second                        | Seconds to minutes              | Minutes (first encounter), near-Tier-2 on cache hit |
| **LLM cost**      | Zero                              | Per-finding inference           | Per-finding generation (first), zero on cache hit   |
| **Coverage**      | 15+ common vulnerability classes  | Any finding in known categories | Any SARIF rule, including never-before-seen types   |
| **Auditability**  | Fully deterministic, reproducible | Readable investigation trail    | Generated analyzer + verdict justification          |
| **Configuration** | None                              | None                            | None                                                |

## Context-Aware Intelligence

A shared intelligence layer enriches all three tiers with codebase context.

**Context signals evaluated on every finding:**

- **Dataflow quality** -- classified on a four-tier scale: strong multi-file, strong single-file, weak, and single-location. Higher dataflow quality increases confidence in true positive verdicts. Weak evidence can downgrade findings that basic reachability would flag as critical.
- **Production vs. test classification** -- a SQL injection in a production API endpoint is critical. The same pattern in a test fixture is not. The system identifies code context and adjusts severity accordingly.
- **Security control detection** -- sanitizers, validators, and framework-specific protections between source and sink are identified and factored into the verdict. This is the difference between "reachable" and "reachable but the input is sanitized before it arrives."
- **Intentionally-vulnerable project filtering** -- demo applications, CTF challenges, and security training repositories generate permanent scanner noise. The system detects these projects and removes them from the triage pipeline.
- **Severity adjustment** -- when context signals indicate real-world risk differs from raw scanner severity, the system adjusts up or down, with a full audit trail showing why.

For the full technical detail on context analysis, see [Context and Intelligence](/how-it-works/context-intelligence).

## Triage Outcomes

Every triage verdict is a structured, machine-processable artifact. Every decision includes the evidence that drove it.

| Status             | Meaning                                                                                                     | Recommended Action                                                                           |
| ------------------ | ----------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| **True Positive**  | The finding is a real, exploitable vulnerability in this code context                                       | Escalate for remediation -- Pixee can generate a fix automatically, or flag for human review |
| **False Positive** | The scanner fired on a pattern that is not exploitable in this context                                      | Suppress from developer view; remove from backlog noise                                      |
| **Won't Fix**      | Technically real but not worth fixing given the context (test code, acceptable risk, compensating controls) | Deprioritize; document the rationale for auditors                                            |
| **Suspicious**     | Insufficient evidence for a definitive verdict                                                              | Route to a security engineer for manual assessment with the available evidence               |

**What ships with every verdict:**

- Typed status (one of the four above, not a numeric score)
- Adjusted severity based on context signals
- Justification prose explaining why this verdict was reached
- Code snippets showing the specific evidence (sanitizer location, dataflow path, framework control)
- Confidence score
- Investigation trail (Tier 2 and Tier 3 verdicts)

**Override capability.** Security engineers can disagree with a verdict and override it. The full evidence is visible, so overrides are informed decisions rather than blind overrules.

**Machine-processable for downstream systems.** Typed statuses (not freeform text) mean dashboards, workflows, and SLA tracking tools can consume verdicts programmatically.

## Triage and Remediation: Closing the Loop

When the triage engine classifies a finding as a true positive, the finding flows directly into Pixee's [fix generation pipeline](/how-it-works/fix-generation). Triage determines what is real. Remediation fixes what is real. Neither capability works at full value without the other.

Auditable triage verdicts support compliance requirements. Structured investigation trails replace manual finding review. Fixes arrive as pull requests in GitHub, GitLab, Azure DevOps, or Bitbucket. See [Fix Safety](/how-it-works/fix-safety) for merge rate data.

## Frequently Asked Questions

### How does automated vulnerability triage reduce false positives?

Pixee routes each finding through a three-tier system. Tier 1 applies deterministic rules for known patterns. Tier 2 uses AI agents to dynamically investigate the codebase. Tier 3 generates custom analyzers for novel rules. Each tier evaluates exploitability in context -- checking dataflow paths, security controls, and production vs. test classification -- to separate real threats from noise. The result is up to 95% false positive reduction across supported scanners. Results vary by workload composition. Known vulnerability patterns handled by deterministic analyzers see the highest reduction rates. Mixed workloads that include novel patterns and custom scanner rules typically see 70-80% reduction as the baseline, with 95% achievable on well-characterized vulnerability classes.

### What is exploitability analysis in application security?

Exploitability analysis determines whether a scanner-reported vulnerability can actually be triggered in a specific codebase. It goes beyond reachability to assess dataflow quality, security control presence, code deployment context, and the strength of evidence supporting an attack path. Pixee evaluates all of these dimensions on every finding, producing auditable verdicts with code-level evidence.

### How do I reduce SAST false positives?

Pixee's triage engine reduces SAST false positives by up to 95% through three mechanisms: deterministic pattern analysis for known vulnerability types, AI-powered investigation for ambiguous cases, and context-aware intelligence that factors in security controls, dataflow quality, and production vs. test classification. Every suppressed finding includes a structured justification for audit defensibility.

### Does the triage system handle custom scanner rules?

Yes. Tier 3 adaptive analysis generates custom triage analyzers on the fly for any rule the system has not encountered before -- including proprietary scanners, custom Semgrep rules, and internal CodeQL queries. Generated analyzers are cached so subsequent findings with the same rule resolve at near-Tier-2 speed. The system's coverage grows automatically as customers connect new scanners.

### How do I know the triage classification is accurate?

Every verdict includes structured evidence: the typed status, justification prose, code snippets showing the specific signals that drove the decision, and a confidence score. Tier 2 and Tier 3 verdicts include a full investigation trail showing every search and reasoning step. Security engineers can review this evidence and override any verdict they disagree with. Your existing SAST re-scanning also applies to validated fixes, closing the verification loop.
