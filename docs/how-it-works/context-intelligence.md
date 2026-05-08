---
title: "Context & Intelligence"
slug: /how-it-works/context-intelligence
track: both
content_type: guide
seo_title: "Context & Intelligence | Beyond Reachability Analysis"
description: How Pixee evaluates dataflow quality, production vs. test context, security controls, and severity signals on every vulnerability finding.
sidebar_position: 6
---

Pixee's context-aware intelligence layer evaluates multiple dimensions of code context to determine whether a vulnerability is actually exploitable -- not just whether it is reachable. The system assesses dataflow quality on a four-tier scale, classifies code as production or test, detects security controls in the code path, filters intentionally-vulnerable projects, and adjusts severity based on all available signals. This shared intelligence substrate enriches both triage verdicts and remediation context. See [Triage Capabilities](/platform/triage) for false positive reduction data.

Context intelligence is the shared layer underneath both of Pixee's co-equal capabilities: [Triage Automation](/how-it-works/triage-engine) and [Remediation Automation](/how-it-works/fix-generation). The same analysis that makes triage verdicts accurate also makes generated fixes higher quality.

## Why Reachability Is Not Enough

Reachability analysis checks whether a vulnerable function is reachable from an entry point. This is a useful first filter -- it removes dead code and internal utilities from consideration. However, reachability alone is not sufficient for accurate triage.

Reachability tells you whether code CAN be reached. It does not tell you whether a vulnerability is actually exploitable in context. Four categories of noise survive basic reachability:

**1. Protected but reachable.** A function may be reachable but sits behind a WAF rule, a framework-provided sanitizer, or an input validation layer. Reachability says "yes, reachable." Exploitability analysis says "yes, reachable, but the input is validated before it arrives -- this is a false positive."

**2. Test code that looks like production.** Test fixtures often exercise the same code paths as production. Reachability analysis treats test code the same as production code. Exploitability analysis classifies code context and adjusts severity.

**3. Weak dataflow evidence.** Some scanner findings are based on pattern matches with no clear taint propagation from source to sink. Reachability does not assess the quality of the evidence. Exploitability analysis does -- weak evidence gets lower confidence, preventing marginal findings from consuming engineering attention.

**4. Severity misalignment.** A "critical" finding in a CTF demo project is not the same as a "critical" finding in a production payment service. Reachability does not adjust severity for deployment context. Exploitability analysis does.

Pixee evaluates all of these dimensions to close the gap between reachability and exploitability.

## Dataflow Quality Assessment

Not all findings have equal evidence. Pixee classifies the strength of dataflow evidence on every finding using a four-tier scale:

| Tier                   | Description                                             | Confidence Impact                          | Gathering Strategy                                                    |
| ---------------------- | ------------------------------------------------------- | ------------------------------------------ | --------------------------------------------------------------------- |
| **Strong Multi-File**  | High-confidence taint propagation across multiple files | Highest confidence in verdicts             | Traces full cross-file dataflow; includes all files in the taint path |
| **Strong Single-File** | High-confidence dataflow within a single file           | High confidence                            | Full file context with highlighted vulnerable region                  |
| **Weak**               | Partial or low-confidence dataflow information          | Reduced confidence; may downgrade findings | Targeted excerpts around the flagged location                         |
| **Single-Location**    | Only the flagged line, no dataflow available            | Lowest confidence                          | Surrounding context with heuristic file matching                      |

**How this affects triage:** Higher dataflow quality increases confidence in true positive verdicts. Weak evidence can downgrade findings that basic reachability would flag as critical. A scanner that reports a SQL injection but provides only a single-location match with no dataflow evidence gets a lower confidence score than the same rule backed by a full source-to-sink trace across multiple files.

**How this affects remediation:** The same classification drives the context gathering strategy for fix generation. Strong multi-file dataflow means the LLM sees the full cross-file taint path. Single-location findings get targeted context with heuristic file matching. Better context means better fixes at lower cost.

## Production vs. Test Classification

A SQL injection pattern in a production API endpoint is critical. The same pattern in a test fixture is not.

The system identifies code context -- production services, test fixtures, integration tests, development utilities -- and adjusts severity accordingly. This means executive dashboards reflect real exploit risk instead of raw rule counts.

This classification is particularly valuable for organizations with large test suites. Test code exercises the same code paths and triggers the same scanner rules as production code, but carries fundamentally different risk. Without production vs. test classification, every test fixture vulnerability inflates the backlog with findings that no one should fix.

## Security Control Detection

When a sanitizer, validator, or framework-specific protection exists between a source and a sink, the system identifies it and uses it as evidence for the triage verdict.

This is the difference between "this function is reachable" and "this function is reachable but the input is sanitized before it arrives."

**How it works:**

- Identifies sanitizers (input validation functions, encoding routines)
- Detects validators (schema validation, type checking)
- Recognizes framework-specific protections (CSRF tokens, Content Security Policy headers, parameterized query builders)
- Every triage verdict includes code snippets showing the relevant controls

Security control detection is what allows the triage engine to confidently classify findings as false positives when a control exists in the code path. Without it, the system would need to escalate every reachable finding for human review.

## Intentionally-Vulnerable Project Filtering

Demo applications, CTF challenges, and security training repositories generate permanent scanner noise. These projects are deliberately insecure -- they exist to teach or test, not to run in production.

The system detects these projects and filters them from the triage pipeline. This prevents wasted triage capacity on findings that are designed to be vulnerable and should never be remediated.

## Severity Adjustment

When context signals indicate that a finding's real-world risk differs from its raw scanner severity, the system adjusts:

- True positive on high-quality dataflow in production stays critical
- Same rule on a weak match in a test fixture gets downgraded
- A finding behind a validated security control may be reclassified as won't-fix

Every severity adjustment includes an audit trail showing why the adjustment was made. Auditors can verify the reasoning. This means compliance teams can explain to auditors why a "critical" scanner finding was downgraded -- the triage verdict includes the specific code signals that justified the decision.

## How Context Feeds Remediation

The context intelligence layer serves double duty. The same analysis that drives triage accuracy also drives fix quality.

**For fix generation:**

- Dataflow quality determines how much code context the LLM sees. Strong multi-file dataflow means the model sees the full taint path. Weak evidence means targeted excerpts.
- Token-budget optimization: targeted excerpts for large files, full files for small ones. Merges consecutive vulnerable regions in the same file to reduce cost.
- Fuzzy file matching finds related files not explicitly named in the dataflow trace.

**Why this matters:** LLM fix quality is bounded by what the model can see. Too little context produces wrong fixes. Too much context wastes tokens and confuses the model. The context intelligence layer solves both problems by adapting the gathering strategy to the finding's dataflow quality.

Better context means better fixes at lower cost. This is the component that caps per-call resource usage without sacrificing fix quality.

## Frequently Asked Questions

### What is exploitability analysis in application security?

Exploitability analysis determines whether a scanner-reported vulnerability can actually be triggered in a specific codebase. It goes beyond reachability to evaluate dataflow quality, security control presence, production vs. test classification, and the strength of evidence supporting an attack path. Pixee evaluates all of these dimensions on every finding, producing auditable verdicts with code-level evidence.

### How does Pixee go beyond basic reachability analysis?

While reachability checks whether a function can be reached from an entry point, Pixee additionally evaluates dataflow quality on a four-tier scale, detects security controls between source and sink, classifies code as production or test, filters intentionally-vulnerable projects, and adjusts severity based on all available context signals. These additional dimensions close the gap between "is this code reachable?" and "is this vulnerability actually dangerous?"

### Does context analysis work across all scanners?

Yes. The context-aware intelligence layer operates across any SARIF-producing scanner. Whether findings come from CodeQL, Semgrep, Checkmarx, or custom internal tools, the same exploitability analysis applies to all findings through a unified pipeline. Triage accuracy scales with the richness of metadata each scanner provides, but every scanner gets context-aware analysis.
