---
title: Triage Capabilities
slug: /platform/triage
track: leader
content_type: conceptual
seo_title: "Triage Automation | Up to 95% False Positive Reduction"
description: How Pixee triages vulnerability findings through three progressive tiers with structured, auditable evidence on every verdict.
sidebar_position: 3
---

Pixee's triage engine classifies every vulnerability finding as true positive, false positive, or won't-fix through codebase-aware exploitability analysis -- not just pattern matching or reachability checks. The three-tier progressive architecture handles known patterns at sub-second speed, investigates ambiguous cases via AI agents, and generates custom analyzers for novel vulnerability types. The result: up to 95% false positive reduction with structured evidence on every verdict, across findings from 12 native scanner integrations.

Triage is co-equal with [remediation](/platform/remediation).

## Three-Tier Progressive Architecture

Pixee routes every finding through a tiered system that applies the cheapest sufficient intelligence. No customer configuration is required -- the routing is automatic.

| Tier                   | Strategy                                                | Speed                                                      | LLM Cost                           | Auditability                                                      | Coverage                                                                                          |
| ---------------------- | ------------------------------------------------------- | ---------------------------------------------------------- | ---------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| **Tier 1: Structured** | 15+ deterministic analyzers                             | Sub-second                                                 | Zero                               | Reproducible -- same input, same output                           | Known vulnerability classes (SQL injection, XSS, command injection, path traversal, and 12+ more) |
| **Tier 2: Agentic**    | AI agents dynamically search the codebase               | Seconds                                                    | Per-finding                        | Readable investigation trail with every search and reasoning step | Ambiguous findings, novel frameworks, custom security controls                                    |
| **Tier 3: Adaptive**   | Generates custom analyzers on the fly, caches for reuse | Minutes (first encounter), near-Tier-2 speed after caching | Per-finding (first encounter only) | Generated analyzer is inspectable                                 | Novel rule types, proprietary scanners, custom rulesets                                           |

**How the fallback works:**

1. A finding arrives from any SARIF-producing scanner.
2. Tier 1 checks whether a deterministic analyzer exists for this vulnerability class. If yes and confidence is sufficient, triage completes at sub-second speed.
3. If Tier 1 cannot decide, the finding routes to Tier 2. An AI agent investigates the codebase -- searching for security controls, tracing dataflow, and building an evidence chain.
4. If Tier 2 cannot resolve the finding (typically because the rule type is novel), Tier 3 generates a custom analyzer, runs it, and caches it for future use.
5. Regardless of which tier resolved it, every finding exits with the same structured verdict.

**Cost efficiency:** Most findings resolve at Tier 1, where there is no LLM cost. Only genuinely complex findings incur AI inference cost. This amortizes AI expense across the full finding volume.

**Self-extending coverage:** Every novel rule type Tier 3 encounters becomes a cached analyzer. The system's coverage grows automatically as customers connect new scanners.

## Beyond Reachability

Reachability analysis checks whether a vulnerable function is reachable from an application entry point. This is a useful first filter, but reachability alone does not determine whether a vulnerability is actually exploitable.

Pixee evaluates multiple context dimensions beyond reachability:

**Dataflow quality.** The system classifies the strength of dataflow evidence on a multi-tier scale. Strong multi-file taint propagation from source to sink is treated differently than a single-location pattern match. Higher dataflow quality increases confidence in true positive verdicts. Weak evidence can downgrade findings that basic reachability would flag as critical.

**Production versus test classification.** A SQL injection pattern in a production API endpoint is critical. The same pattern in a test fixture is not. Pixee distinguishes between these contexts and adjusts severity accordingly, so dashboards reflect real exploit risk rather than raw rule counts.

**Security control detection.** When a sanitizer, validator, or framework-specific protection exists between a source and a sink, the system identifies it and factors it into the verdict. This is the difference between "this function is reachable" and "this function is reachable but the input is sanitized before it arrives."

**Intentionally-vulnerable project filtering.** Demo applications, CTF challenges, and security training repositories generate permanent noise in upstream scanners. Pixee detects these projects and filters them out of the triage pipeline.

**Severity adjustment.** When context signals indicate that a finding's real-world risk differs from its raw scanner severity, the system adjusts up or down. A true positive with strong dataflow in production stays critical. The same rule on a weak match in a test fixture gets downgraded.

## Structured, Auditable Outcomes

Every triage verdict is a structured, machine-processable artifact. Every decision includes the evidence that drove it.

| Verdict Component                  | What It Contains                                                                                              |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| **Typed status**                   | True Positive, False Positive, Won't Fix, or Suspicious -- not a numeric score                                |
| **Adjusted severity**              | Severity re-ranked based on context signals (production vs. test, dataflow quality, control presence)         |
| **Justification prose**            | Human-readable explanation of why this verdict was reached                                                    |
| **Code snippets**                  | Specific code evidence -- the sanitizer location, dataflow path, or framework control that drove the decision |
| **Confidence score**               | Quantified confidence in the verdict                                                                          |
| **Investigation trail** (Tier 2/3) | Step-by-step record of agent searches, control checks, and reasoning chain                                    |

**Audit defensibility.** Compliance officers and auditors see exactly why a finding was suppressed. The justification and code snippets provide a defensible record for every triage decision.

**Developer trust.** Developers see the sanitizer or control that justified a false positive verdict. This builds trust in the system and provides visibility into the reasoning.

**Machine processability.** Typed statuses mean downstream systems can consume verdicts programmatically -- dashboards, workflow triggers, SLA tracking, and SIEM integrations all work with structured data rather than freeform text.

**Override capability.** Security engineers can disagree with a verdict and override it, because they can see exactly what evidence the system used and where it may have been insufficient.

Pixee triage verdicts are advisory. Your security team retains final authority over all classification decisions and can override any verdict. When Pixee classifies a finding as FALSE_POSITIVE but your team disagrees, the override is recorded and used to improve future classifications for your codebase.

## Scanner-Agnostic Coverage

Triage works across any SARIF-producing scanner. Customers with heterogeneous stacks -- multiple commercial scanners plus custom rules -- get a single triage layer that handles all of it.

- **12 native integrations** with scanner-specific metadata extraction (CodeQL, SonarQube, Checkmarx, Veracode, Snyk, Semgrep, AppScan, Polaris, GitLab SAST, Trivy, Datadog SAST, Arnica SAST)
- **Universal SARIF ingestion** for any additional scanner (50+ validated)
- **Custom rule coverage** -- proprietary Semgrep rules, internal CodeQL queries, and custom scanner rulesets are handled by Tier 2 and Tier 3 without vendor integration work
- **Cross-tool deduplication** -- when multiple scanners flag the same finding, the system eliminates duplicates

The triage layer sits above your existing detection stack. You do not need to change, consolidate, or replace any scanners to use Pixee.

## Frequently Asked Questions

### How does automated vulnerability triage reduce false positives?

Pixee analyzes each finding's exploitability in the context of your specific codebase -- checking dataflow paths, security controls, production versus test classification, and code context -- rather than relying on pattern matching alone. This context-aware approach eliminates up to 95% of false positives with structured evidence on every verdict. Results vary by workload composition. Known vulnerability patterns handled by deterministic analyzers see the highest reduction rates. Mixed workloads that include novel patterns and custom scanner rules typically see 70-80% reduction as the baseline, with 95% achievable on well-characterized vulnerability classes.

### What is exploitability analysis in application security?

Exploitability analysis determines whether a scanner-reported vulnerability can actually be triggered in a specific codebase. It goes beyond simple reachability to evaluate dataflow quality, security control presence, and deployment context. The result is a verdict based on real exploit risk, not theoretical pattern matches.

### Does Pixee work with multiple scanners at the same time?

Yes. Pixee ingests findings from 12 natively integrated scanners plus any tool that produces SARIF output, providing unified triage across your entire scanner portfolio through a single pipeline. Customers running heterogeneous stacks get a single triage layer without per-scanner configuration.

### What happens when Pixee encounters a scanner rule it has never seen?

Tier 3 of the triage architecture generates a custom analyzer on the fly for novel rule types. That analyzer is cached, so the next finding with the same rule resolves faster. The system's coverage extends itself as customers connect new scanners -- no manual rule authoring or vendor integration requests required.

### How do I know the triage verdicts are accurate?

Every verdict includes the structured evidence that drove the decision -- specific code paths, security controls, dataflow evidence, and reasoning. Security engineers can review the evidence, validate the logic, and override any verdict. Tier 1 verdicts are deterministic and reproducible: same input, same output, every time.
