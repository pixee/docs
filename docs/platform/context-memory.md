---
title: "Context, Memory & Preferences"
slug: /platform/context-memory
track: both
content_type: conceptual
seo_title: "Context, Memory & Preferences | How Pixee Learns Your Codebase"
description: How Pixee reads your codebase, adapts to team conventions, and improves from feedback signals to deliver context-aware fixes.
sidebar_position: 4
---

Pixee is not a generic code scanner that applies one-size-fits-all patches. It reads your repository, learns your team's conventions and frameworks, and improves from the feedback your team provides when it reviews and merges fixes. This page explains how that context is gathered, stored, and used.

## Codebase Context

Before Pixee generates a fix, it analyzes the repository for the patterns, frameworks, and security controls already in use. This context shapes every fix Pixee produces.

**What Pixee reads:**

- **Existing patterns and conventions** — naming conventions, preferred utility classes, error handling patterns, code style. If your team wraps SQL calls in a `DatabaseHelper`, Pixee generates fixes that use `DatabaseHelper`, not a raw JDBC pattern.
- **Frameworks and libraries in use** — Spring Boot, Django, Express, ASP.NET Core, and others each have idiomatic secure coding patterns. Pixee's framework-aware fixes match what your team already uses.
- **Dependencies** — the libraries and versions in your manifest files inform what fix patterns are available and safe. If your project already includes an input validation library, Pixee prefers it over introducing a new dependency.
- **Existing security controls** — middleware, sanitization utilities, authentication layers, and framework-provided security features. A finding protected by framework-level controls is classified differently from the same pattern without protection.

This analysis is performed at the repository level for each analysis run. Code is not stored after the analysis completes. See [Security Architecture](/enterprise/security-architecture) for data handling details.

## PIXEE.yaml

Team-level preferences and repository configuration are specified in a `PIXEE.yaml` file in the repository root. PIXEE.yaml is the primary mechanism for telling Pixee how to behave in your repository.

Common configuration includes:

- Scoping fix generation to specific severity levels, vulnerability types, or repository paths
- Excluding files, directories, or patterns from analysis
- Setting branch targeting preferences
- Configuring PR batching and delivery behavior

PIXEE.yaml is optional — Pixee works with sensible defaults without it. For the full schema and all available options, see [PIXEE.yaml Reference](/configuration/pixee-yaml).

## Learning from Feedback

Pixee improves from the signals your team sends when it interacts with Pixee-generated PRs. These signals are the primary mechanism by which Pixee adapts to your team's preferences and risk tolerance over time.

**Signals Pixee collects:**

| Signal | What It Means |
|---|---|
| PR merged (as-is) | Fix was correct and matched team conventions — positive signal for this fix pattern |
| PR merged (with modifications) | Fix was directionally correct but needed adjustment — Pixee notes the delta |
| PR closed / declined | Fix was not accepted — negative signal for this finding type or fix approach |
| Triage override | Team disagreed with Pixee's classification — updates classification logic for similar findings |

**Scope of learning:** [NEEDS VERIFICATION: whether feedback signals apply at per-repo scope, org-level scope, or both. Current understanding is that signals apply at the repository level and may aggregate to org level over time.]

**Observing improvement:** Teams that have been using Pixee for several weeks typically see reduced false positive rates and higher merge rates as the system calibrates to their codebase and review preferences. [NEEDS VERIFICATION: specific time windows and observable metrics for feedback loop effects.]

## Triage Overrides

When Pixee classifies a finding as a true positive but your team disagrees — or vice versa — you can override the triage verdict. Overrides are the strongest feedback signal available.

**How to override:** [NEEDS VERIFICATION: specific UI mechanics for submitting a triage override — whether this is done via PR comment, dashboard action, or PIXEE.yaml configuration.]

**What happens when you override:**
- The specific finding's verdict is updated immediately.
- The override is recorded with the rationale (if provided).
- Future findings matching the same pattern in the same codebase context receive adjusted classification.

**Influence on future classifications:** Triage overrides influence how Pixee classifies similar findings going forward. The more specific the context (same rule ID, same file pattern, same framework), the more targeted the adjustment. [NEEDS VERIFICATION: the exact scope and mechanism by which overrides propagate to future similar findings.]

## Enterprise Context

For organizations with specific policies — approved libraries, banned patterns, internal framework conventions — surfacing that context to Pixee allows fix generation to align with enterprise standards rather than generic open-source patterns.

**Mechanisms for providing enterprise context:**

- **PIXEE.yaml** — per-repository configuration for fix scope and behavior preferences.
- **Codebase reading** — Pixee automatically detects internal libraries and frameworks by analyzing imports, dependency manifests, and usage patterns. If your organization uses an internal HTTP client wrapper, Pixee detects it and uses it in fixes.

[NEEDS VERIFICATION: whether there is a dedicated enterprise-level configuration mechanism beyond PIXEE.yaml for specifying approved libraries, banned patterns, or internal framework conventions at the organization level. Contact your Pixee account team for current enterprise context configuration options.]

For organizations managing hundreds of repositories, the [Phased Rollout Guide](/enterprise/phased-rollout) covers organization-wide deployment strategy that accounts for repository-level variation in conventions and risk tolerance.
