---
title: Welcome to Pixee
slug: /
track: dev
content_type: tutorial
seo_title: "Get Started with Pixee | Automated Security Remediation"
description: Install Pixee and connect your repositories for automated vulnerability triage and remediation via pull requests.
sidebar_position: 1
---

Pixee automates vulnerability triage and remediation directly inside your existing pull request workflow. Install the GitHub App, GitLab integration, Azure DevOps extension, or Bitbucket connector, and Pixee starts delivering fixes as standard PRs your developers already know how to review and merge. No new dashboards. No new interfaces. Setup takes under five minutes, and most teams see their first automated fix within the hour.

Pixee is not a scanner. It works downstream of your existing SAST, SCA, and DAST tools — ingesting their findings, triaging them for exploitability, and generating validated fixes.

## What Pixee Does

Pixee provides two co-equal capabilities:

**Triage Automation** reduces false positives by up to 95%. Each scanner finding passes through exploitability analysis that determines whether the vulnerability is actually reachable and triggerable in your codebase — not just whether it matches a pattern. Findings classified as false positives include a structured justification explaining why, so your security team can audit the decision.

**Remediation Automation** generates context-aware code fixes and delivers them as pull requests. Developers review and merge these PRs like any other code change. Across production deployments, 76% of Pixee-generated fixes are merged by development teams after human review.

Both capabilities work together. Triage eliminates the noise. Remediation fixes what remains. The combination reduces vulnerability backlog resolution time.

| Capability  | What It Does                                                  | Proof Point                              |
| ----------- | ------------------------------------------------------------- | ---------------------------------------- |
| Triage      | Exploitability analysis across 12 native scanner integrations | Up to 95% false positive reduction       |
| Remediation | Context-aware fixes as pull requests                          | 76% merge rate on production deployments |
| Delivery    | Standard PRs in GitHub, GitLab, ADO, Bitbucket                | Native platform integration              |

## Choose Your Platform

| Platform         | Setup Time | Guide                                                 |
| ---------------- | ---------- | ----------------------------------------------------- |
| **GitHub**       | ~3 minutes | [GitHub Setup →](/getting-started/github)             |
| **GitLab**       | ~5 minutes | [GitLab Setup →](/getting-started/gitlab)             |
| **Azure DevOps** | ~5 minutes | [Azure DevOps Setup →](/getting-started/azure-devops) |
| **Bitbucket**    | ~5 minutes | [Bitbucket Setup →](/getting-started/bitbucket)       |

Already running CI/CD pipelines? See [CI/CD Integration](/getting-started/ci-cd) for pipeline-level setup.

Want to drive the platform from the command line — query scans, configure workflows, hit the API? See [Pixee CLI](/getting-started/cli).

Need enterprise deployment (self-hosted, air-gapped, BYOM)? Start with [Enterprise Deployment Options](/enterprise/deployment).

## What Happens After Install

1. Pixee connects to your repositories and ingests findings from your connected scanners.
2. The triage engine classifies each finding as true positive, false positive, or won't-fix — with a structured justification for every decision.
3. For confirmed vulnerabilities with available fixes, Pixee opens a pull request containing the fix, the vulnerability context, and quality scores.
4. Your developers review the PR in their normal workflow — same code review process, same CI/CD pipeline, same branch protection rules.
5. Developers merge, modify, or close the PR. No special tooling required.

There is no Pixee dashboard you need to monitor. The PR is the interface.

## Developer Journey

This Getting Started section walks you through a complete path:

**Install** → **Connect scanners** → **Review your first fix** → **Merge**

| Step                                | Page                                                                                                                                                   | Time     |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | -------- |
| 1. Install the platform integration | [GitHub](/getting-started/github), [GitLab](/getting-started/gitlab), [ADO](/getting-started/azure-devops), or [Bitbucket](/getting-started/bitbucket) | 3-5 min  |
| 2. Connect your scanner (optional)  | [CI/CD Integration](/getting-started/ci-cd)                                                                                                            | 5-10 min |
| 3. Review and merge your first fix  | [Your First Fix](/getting-started/first-fix)                                                                                                           | 5 min    |

Total time to first merged fix: under 30 minutes for most teams.

## Prerequisites

- A GitHub, GitLab, Azure DevOps, or Bitbucket account with at least one repository
- Code in a supported language: Java, Python, JavaScript/TypeScript, .NET, Go, or PHP
- Existing scanner findings recommended for immediate triage and remediation results. Without connected scanner results, Pixee can apply proactive security hardening codemods to common vulnerability patterns.

No agents to install. No CLI required for the standard workflow. No configuration files needed to start.

## Large Backlogs (10,000+ Findings)

Pixee handles large vulnerability backlogs without overwhelming your development team. Findings are prioritized by severity -- Critical and High findings are processed first, so the most dangerous vulnerabilities get addressed before lower-priority items.

PR creation is batched, not instantaneous. Expect a steady stream of fixes delivered over days, not a flood of hundreds of PRs at once. This pacing keeps code review manageable and avoids overwhelming CI/CD pipelines.

Use a [PIXEE.yaml](/configuration/pixee-yaml) file to scope initial remediation to specific severity levels, vulnerability types, or repository paths. This gives your team control over the rollout pace and lets you focus on the findings that matter most.

For organizations managing hundreds of repositories or millions of findings, the [Phased Rollout Guide](/enterprise/phased-rollout) covers rollout strategy for large estates -- including recommended phasing, success metrics per phase, and organizational change management.

## Frequently Asked Questions

### How do I install Pixee?

Choose your platform (GitHub, GitLab, Azure DevOps, or Bitbucket), authorize the app, select your repositories, and Pixee begins analyzing findings automatically. Setup takes under five minutes. See the platform-specific guides linked above.

### How long does it take to see results?

Most teams see their first automated fix within one hour of installation. Triage results appear as soon as scanner findings are ingested. The timeline depends on how many findings your scanners have already produced.

### Does Pixee require code changes to install?

No. Pixee installs as a platform integration (GitHub App, GitLab webhook, Azure DevOps extension, Bitbucket connector) and requires zero code changes, CLI installs, or configuration files to start.

### Do developers need to learn a new tool?

No. Developers interact with Pixee exclusively through pull requests in their existing platform. There is no new interface, no new CLI, no new dashboard. Reviewing a Pixee PR is identical to reviewing any other code change.
