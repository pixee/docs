---
title: Phased Rollout Guide
slug: /enterprise/phased-rollout
track: leader
content_type: guide
seo_title: Phased Rollout Guide - From Pilot to Enterprise-Wide Security Automation
description: Roll out Pixee from a single repository to your entire organization with decision gates, success criteria, and rollback plans at every phase.
sidebar_position: 10
---

Pixee deploys in phases: single repository, team, org unit, enterprise. Each phase has defined success criteria, a decision gate, and a rollback path. This guide gives security leaders the planning framework and security engineers the execution checklist. Most teams complete Phase 1 (single-repo pilot) within one week and reach Phase 3 (org unit) within 30-45 days.

## Overview

Pixee deploys in phases to validate triage accuracy and fix quality on a controlled scope before expanding. Each phase generates metrics that inform the next expansion decision. Phase 1 data feeds the metrics tracked in [Enterprise Overview > Measuring Success](/enterprise/overview#measuring-success).

## Phase Model Overview

| Phase                   | Scope                                 | Duration  | Decision Gate                                                | Who Leads                     |
| ----------------------- | ------------------------------------- | --------- | ------------------------------------------------------------ | ----------------------------- |
| **Phase 1: Pilot**      | 1-3 repositories                      | 1-2 weeks | Merge rate above 50%, zero incidents                         | Security Engineer             |
| **Phase 2: Team**       | Single team (5-15 repos)              | 2-4 weeks | Team merge rate stable, developer feedback positive          | Security Engineer + Team Lead |
| **Phase 3: Org Unit**   | Division or business unit (50+ repos) | 4-8 weeks | Consistent metrics across teams, support processes validated | Head of AppSec                |
| **Phase 4: Enterprise** | All repositories                      | Ongoing   | Executive sign-off, compliance requirements met              | CISO / Head of AppSec         |

Timeline expectations are ranges, not commitments. Actual pace depends on your team size, internal approval processes, and compliance requirements.

## Phase 1: Pilot

Phase 1 is where most readers will start and where the most specific guidance matters.

### Security Leader Planning Track

**Selecting pilot repositories.** Choose repos that have active development, existing scanner findings, and engaged developers. Avoid dormant repositories or repos with no current security findings -- they produce no data. The best pilot candidates are repos where the security team already knows about unresolved findings.

**Defining success criteria.** Set explicit thresholds before the pilot begins: merge rate above 50%, zero false fixes (no PR that introduces a bug or breaks tests), and at least one developer who voluntarily merges a Pixee PR without prompting. Write these down.

**Internal communication.** Notify the development team that a pilot is starting on selected repositories.

### Security Engineer Execution Track

**Installation.** Connect Pixee to the pilot repositories. See the Getting Started guides for [GitHub](/getting-started/github), [GitLab](/getting-started/gitlab), [Azure DevOps](/getting-started/azure-devops), or [Bitbucket](/getting-started/bitbucket).

**Scanner connection.** Connect your existing scanners to Pixee so it can triage and remediate findings from your current tooling. Pixee works with 13 native scanner integrations and any SARIF-producing scanner.

**First fix review.** Walk through the first Pixee PR with the development team. Explain what changed, why it changed, and the quality scores.

**Metrics collection.** Track merge rate, triage volume, and developer response time from the Pixee dashboard.

### Phase 1 Success Criteria

| Criterion          | Threshold                                         | How to Measure                  |
| ------------------ | ------------------------------------------------- | ------------------------------- |
| Merge rate         | Above 50% (first-week industry average)           | Pixee dashboard: fix activity   |
| False fixes        | Zero (no PR that breaks tests or introduces bugs) | CI/CD results on Pixee PRs      |
| Voluntary adoption | At least one developer merges without prompting   | Observation / PR history        |
| Triage value       | Triage automation reduces manual review volume    | Pixee dashboard: triage summary |

## Phase 2: Team Expansion

### Security Leader Planning Track

Expand from champion repositories to team-wide deployment. Set team-level merge rate targets based on Phase 1 data. Establish fix review norms: who reviews Pixee PRs, what response time is expected.

Use Phase 1 metrics to evaluate whether expansion is warranted. The metrics tracked in [Enterprise Overview > Measuring Success](/enterprise/overview#measuring-success) provide the data points for Phase 3 decision-making.

### Security Engineer Execution Track

Onboard additional repositories across the team. Configure team-level policies in PIXEE.yaml for consistent behavior. Train developers on the PR review workflow -- most questions in Phase 2 are about process, not product.

Monitor for edge cases across different codebases. Languages, frameworks, and coding patterns vary within a team. Phase 2 surfaces these variations before org-wide deployment.

### Decision Gate

Stable merge rate across team repos, positive developer feedback (survey or informal), no unresolved incidents. If the gate is not met, diagnose the issue before expanding -- do not push forward on momentum alone.

## Phase 3: Org Unit

### Security Leader Planning Track

Multi-team coordination is the primary challenge in Phase 3. Different teams may use different scanner stacks and languages. Align Pixee metrics with compliance reporting requirements. Define the support model: who handles developer questions and escalations.

Build the executive reporting dashboard for Phase 4 approval. Present triage reduction, merge rate trends, MTTR improvement, and compliance acceleration across all enrolled teams.

### Security Engineer Execution Track

Scale repository configuration across teams using PIXEE.yaml. Verify language coverage across the org unit (see [Languages > Overview](/languages/overview)). Integrate Pixee reporting with existing CI/CD pipelines and dashboards. Set up observability (see [Observability](/enterprise/observability)) if running a self-hosted deployment.

### Decision Gate

Consistent metrics across all enrolled teams, compliance team sign-off on audit evidence, support processes validated and documented.

## Phase 4: Enterprise Rollout

### Security Leader Planning Track

Executive sign-off requires presenting Phase 3 results with the metrics tracked in [Enterprise Overview > Measuring Success](/enterprise/overview#measuring-success): merge rate, triage reduction, MTTR, and compliance window adherence.

Make enterprise deployment model decisions at this stage -- cloud SaaS, embedded cluster, Helm, or air-gapped based on compliance requirements. See [Deployment Options](/enterprise/deployment).

### Security Engineer Execution Track

Configure SSO and access control for enterprise-wide access. Set up reporting and dashboards for ongoing operations. Establish the maintenance cadence for upgrades (approximately every two weeks for Pixee Enterprise).

## Rollback Plan

Pixee is additive. If any phase does not meet success criteria, disabling Pixee is straightforward and carries zero risk to existing code.

| Action                     | What Happens                                                                   |
| -------------------------- | ------------------------------------------------------------------------------ |
| **Disable per-repository** | Pixee stops opening PRs for that repository. Existing code is unchanged.       |
| **Disable per-team**       | Team-level rollback without affecting other teams.                             |
| **Disable entirely**       | All Pixee PRs stop. No existing code changes. No runtime dependency to remove. |
| **Data preservation**      | All triage decisions and fix history persist even if Pixee is paused.          |

Disabling Pixee at any phase does not affect existing code. Previously merged fixes remain as standard code in your repositories. There is no runtime dependency on Pixee for code that has been merged.

## Identifying Internal Champions

A champion is a developer who actively uses Pixee PRs during the pilot phase and can support other teams during expansion. Typical indicators: merges Pixee PRs early, reviews PR descriptions and quality scores in detail, and asks about framework coverage.

**Enablement:** Share the [Languages > Overview](/languages/overview) page (coverage matrix) and this rollout guide. Provide access to the metrics from [Enterprise Overview > Measuring Success](/enterprise/overview#measuring-success).

## Multi-Business-Unit Rollout

Organizations with multiple business units face a sequencing decision: which BU goes first? Starting with the most mature BU -- the one with the strongest security practices and most engaged developers -- typically produces the cleanest pilot data for evaluating expansion.

**Different scanner stacks per BU are not a problem.** Pixee handles multiple scanners simultaneously. If one BU runs Checkmarx and another runs Veracode, each BU's scanner connects independently through the same triage and remediation pipeline. No configuration conflicts, no scanner migration required.

**Per-BU configuration via PIXEE.yaml.** Each business unit can maintain its own PIXEE.yaml with different severity thresholds, excluded directories, and PR volume settings. A conservative BU can start with critical-only findings while a more mature BU runs full scope -- both within the same Pixee deployment.

**Expansion timeline.** After the first BU completes Phase 1 and Phase 2, budget 2-4 weeks per additional business unit. Each subsequent BU benefits from the configuration playbook and PIXEE.yaml templates the first BU established.

## PIXEE.yaml Configuration for Phased Rollout

PIXEE.yaml controls the scope of triage and remediation per repository or business unit. Use these example configurations to match each rollout phase.

**Conservative (Phase 1 pilot):** Critical findings only, exclude test directories.

```yaml
# Conservative (Phase 1 pilot): Critical findings only, exclude tests
severity:
  minimum: CRITICAL
exclude:
  paths:
    - "**/test/**"
    - "**/tests/**"
    - "**/*Test.java"
```

**Moderate (Phase 2 expansion):** Critical and high findings, all directories included.

```yaml
# Moderate (Phase 2 expansion): Critical + High, all directories
severity:
  minimum: HIGH
```

**Full scope (Phase 3+):** All severities, no exclusions.

```yaml
# Full scope (Phase 3+): All severities
severity:
  minimum: LOW
```

Each business unit or team can use a different configuration during rollout. As confidence builds, adjust the severity threshold downward and remove directory exclusions. See [PIXEE.yaml Reference](/configuration/pixee-yaml) for the complete configuration reference.

