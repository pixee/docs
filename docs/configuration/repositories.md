---
title: Repository Management
slug: /configuration/repositories
track: dev
content_type: guide
seo_title: Repository Management -- Pixee Docs
description: Add, remove, pause, and organize repositories monitored by Pixee across GitHub, GitLab, Azure DevOps, and Bitbucket.
sidebar_position: 3
---

# Repository Management

Pixee can monitor any repository accessible through your connected SCM platform. Add repositories individually or in bulk, organize them by team or business unit, and control which repos receive Triage Automation, Remediation Automation, or both. Repository management is handled through the Pixee dashboard and works identically across GitHub, GitLab, Azure DevOps, and Bitbucket.

## Adding Repositories

### Single repository

From the Pixee dashboard, select your SCM connection and choose the repository to add. Pixee runs an initial analysis and opens PRs for any findings it can triage or fix. First results typically appear within minutes.

### Bulk onboarding

For organizations with dozens or hundreds of repositories, Pixee supports bulk addition. Select multiple repositories from the dashboard or use the API to onboard repositories programmatically.

### What happens when a repo is added

1. Pixee scans the repository for connected scanner findings (SARIF imports, native scanner integrations).
2. Triage Automation classifies findings as true positives, false positives, or won't-fix.
3. Remediation Automation generates fixes for actionable findings using deterministic codemods plus AI-powered fixes.
4. PRs appear in your normal SCM workflow for review and merge.

### Platform-specific notes

How Pixee discovers repositories depends on the SCM platform:

| Platform     | Discovery Method            | Notes                                                                                                                                              |
| ------------ | --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| GitHub       | GitHub App installation     | Select "All repositories" or specific repos during App install. Auto-discovers new repos if granted org-wide access.                               |
| GitLab       | Personal access token (PAT) | Scopes: `api`, `read_user`, `read_repository`, `read_api`, `write_repository`. Use `member_projects_only` to restrict to explicit-member projects. |
| Azure DevOps | Personal access token (PAT) | Supports webhook configuration and optional work-item linking for orgs with branch policies.                                                       |
| Bitbucket    | API token                   | Supports Bitbucket Cloud and Bitbucket Server.                                                                                                     |

## Removing and Pausing Repositories

### Removing a repository

Remove a repository from the Pixee dashboard to stop all analysis and PR creation. Existing open PRs remain in your SCM (close them manually or let Pixee clean them up during removal). No Pixee data is retained for removed repositories.

### Pausing vs. removing

| Action     | Effect                                              | Use when                                                         |
| ---------- | --------------------------------------------------- | ---------------------------------------------------------------- |
| **Pause**  | Stops analysis temporarily; configuration preserved | Repository is under heavy development, team wants a quiet period |
| **Remove** | Stops analysis permanently; configuration cleared   | Repository is decommissioned or no longer in scope               |

Pausing keeps your PIXEE.yaml and dashboard settings intact so you can resume without reconfiguration.

## Repository Organization

### Grouping and filtering

The Pixee dashboard supports organizing repositories by team, business unit, or application. Use filters and search to navigate large repository counts.

For each repository, the dashboard shows:

- **Last analysis:** When Pixee last scanned the repo
- **Active PRs:** Open Pixee PRs awaiting review
- **Merge rate:** Percentage of Pixee PRs merged by developers
- **Triage summary:** Breakdown of findings by classification

### Scaling to many repositories

Teams with 50+ repositories benefit from grouping. Assign repositories to logical groups that match your organizational structure. This also simplifies notification routing and reporting -- configure alerts at the group level rather than per-repo.

## Repository-Level Settings

Each repository inherits organization-wide defaults. Override specific settings in two ways:

- **PIXEE.yaml** (in-repo): Developers control path exclusions, finding suppressions, fix toggles, and PR formatting. See [PIXEE.yaml Reference](/configuration/pixee-yaml).
- **Dashboard overrides**: Security leads can override scheduling and notification settings per-repository from the Pixee dashboard.

Settings that can be overridden at the repository level:

| Setting              | PIXEE.yaml | Dashboard |
| -------------------- | ---------- | --------- |
| Path exclusions      | Yes        | --        |
| Finding suppressions | Yes        | --        |
| Fix type toggles     | Yes        | --        |
| PR formatting        | Yes        | --        |
| Scan schedule        | --         | Yes       |
| Notification routing | --         | Yes       |

## Multi-SCM Support

A single Pixee deployment supports repositories from multiple SCM platforms simultaneously. Connect GitHub, GitLab, Azure DevOps, and Bitbucket to the same Pixee organization and manage all repositories from one dashboard.

Cross-platform visibility means your security team sees triage results and fix activity across every connected repository, regardless of which SCM hosts it.

Enterprise self-hosted deployments have the same multi-SCM support. See [Enterprise > Deployment Options](/enterprise/deployment) for infrastructure details.
