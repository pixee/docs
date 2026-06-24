---
title: Welcome to Pixee
slug: /
track: dev
content_type: tutorial
seo_title: "Get Started with Pixee | Automated Security Remediation"
description: Install Pixee and connect your scanners for automated vulnerability triage and remediation via pull requests.
sidebar_position: 1
---

Pixee automates vulnerability triage and remediation directly inside your existing pull request workflow. Install the GitHub App — or a source control access token for GitLab, Bitbucket, or Azure DevOps — connect your scanners, and Pixee starts delivering fixes as standard PRs your developers already know how to review and merge. Setup takes under five minutes, and most teams see their first automated fix within the hour.

Pixee is not a scanner. It works downstream of your existing SAST, SCA, and DAST tools — ingesting their findings, triaging them for exploitability, and generating validated fixes.

## What Pixee Does

Pixee provides two co-equal capabilities:

**Triage Automation** reduces false positives by up to 98%. Each scanner finding passes through exploitability analysis that determines whether the vulnerability is actually reachable and triggerable in your codebase — not just whether it matches a pattern. Every verdict includes a structured justification with the specific code evidence that drove the decision.

**Remediation Automation** generates context-aware code fixes and delivers them as pull requests. Developers review and merge these PRs like any other code change. Across production deployments, 76% of Pixee-generated fixes are merged by development teams after human review.

Both capabilities work together. Triage eliminates the noise. Remediation fixes what remains.

| Capability  | What It Does                                                | Proof Point                              |
| ----------- | ----------------------------------------------------------- | ---------------------------------------- |
| Triage      | Exploitability analysis across natively integrated scanners | Up to 98% false positive reduction       |
| Remediation | Context-aware fixes as pull requests                        | 76% merge rate on production deployments |
| Delivery    | Standard PRs in GitHub, GitLab, ADO, Bitbucket              | Native platform integration              |

## Setup Flow

Setting up Pixee takes three steps:

| Step                                    | Page                                                      | Time     |
| --------------------------------------- | --------------------------------------------------------- | -------- |
| 1. Connect your source control platform | [Connect Source Control](/getting-started/source-control) | 3-5 min  |
| 2. Connect your scanners                | See below — required                                      | 5-10 min |
| 3. Review and merge your first fix      | [Your First Fix](/getting-started/first-fix)              | 5 min    |

Total time to first merged fix: under 30 minutes for most teams.

## Connecting Scanners (Required)

:::warning[Scanners are required]
Pixee requires scanner findings to perform triage and generate fixes. Without at least one connected scanner, there is nothing for Pixee to act on. Installing Pixee without connecting a scanner will not produce any results.
:::

**What "connecting a scanner" means:**

- For scanners that write to your SCM's code-scanning surface (GitHub Code Scanning, GitLab Security Dashboard, etc.), Pixee ingests findings automatically through the SCM integration — no additional step required.
- For scanners that don't write to the SCM's code-scanning surface, upload SARIF results to the SCM's code-scanning API as a CI step. Pixee then ingests them through the SCM integration.
- For natively integrated scanners, configure the scanner connection directly in Pixee. Pixee pulls results automatically — no SARIF upload or CI step required. See [Integrations Overview](/integrations/overview) for the list of supported native integrations.

Pixee integrates natively with a growing list of scanners including CodeQL, Semgrep, Checkmarx, Veracode, Snyk Code, SonarQube, AppScan, Polaris, Fortify, Contrast, GitLab SAST, GitLab SCA, and Trivy. Any SARIF-producing scanner also works. See [Scanner Integration](/platform/scanner-integration) for the full list and [CI/CD Integration](/integrations/ci-cd) for pipeline setup examples.

## Choose Your Platform

See [Connect Source Control](/getting-started/source-control) for a quick-start summary of all four platforms (GitHub, GitLab, Azure DevOps, Bitbucket) with connection requirements and step summaries. Full setup guides live under [Integrations → Source Control](/integrations/overview).

Need enterprise deployment (self-hosted, air-gapped, BYOM)? Start with [Enterprise Deployment Options](/enterprise/deployment).

## What Happens After Install

1. Pixee connects to your repositories and ingests findings from your connected scanners.
2. The triage engine classifies each finding as true positive, false positive, or won't-fix — with a structured justification for every decision.
3. For confirmed vulnerabilities with available fixes, Pixee opens a pull request containing the fix, the vulnerability context, and quality scores.
4. Your developers review the PR in their normal workflow — same code review process, same CI/CD pipeline, same branch protection rules.
5. Developers merge, modify, or close the PR. No special tooling required.

## Prerequisites

- A GitHub, GitLab, Azure DevOps, or Bitbucket account with at least one repository
- At least one connected scanner — this is required for triage and remediation to work

No agents to install. No CLI required for the standard workflow. No configuration files needed to start.

## Large Backlogs (10,000+ Findings)

Pixee handles large vulnerability backlogs without overwhelming your development team. Findings are prioritized by severity — Critical and High findings are processed first.

PR creation is batched, not instantaneous. Expect a steady stream of fixes delivered over days, not a flood of hundreds of PRs at once.

Use a [PIXEE.yaml](/configuration/pixee-yaml) file to scope initial remediation to specific severity levels, vulnerability types, or repository paths.

For organizations managing hundreds of repositories or millions of findings, the [Phased Rollout Guide](/enterprise/phased-rollout) covers rollout strategy for large estates.
