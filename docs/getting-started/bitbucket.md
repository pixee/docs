---
title: Bitbucket Setup
slug: /getting-started/bitbucket
track: dev
content_type: tutorial
seo_title: "Set Up Pixee for Bitbucket | Automated Security PRs"
description: Install Pixee for Bitbucket to receive automated vulnerability triage and remediation as pull requests.
sidebar_position: 5
---

Install Pixee for Bitbucket to receive automated vulnerability triage and remediation as standard pull requests in your existing Bitbucket workflow. Connect your Bitbucket workspace, select your repositories, and Pixee begins delivering fixes that developers review and merge using the same PR process they already use. Works with Bitbucket Cloud and Bitbucket Server. No separate tools, no new dashboards to learn.

## Prerequisites

Before you start, confirm the following:

- **Bitbucket permissions.** You need Admin permissions on the target workspace (Bitbucket Cloud) or Project Admin permissions (Bitbucket Server).
- **Bitbucket instance.** Bitbucket Cloud (bitbucket.org) or Bitbucket Data Center / Server. See [Bitbucket Data Center / Server](#bitbucket-data-center--server) below for on-premises details.
- **Supported language.** At least one repository with code in Java, Python, JavaScript/TypeScript, .NET, Go, or PHP.
- **Scanner results (required).** Pixee needs scanner findings to perform triage and generate fixes. If you run scanners through Bitbucket Pipelines or a separate CI system (Snyk, SonarQube, Checkmarx, or others), Pixee can ingest those findings.

No Bitbucket app marketplace installs required. No `bitbucket-pipelines.yml` changes needed to start.

## Setup

Create a Bitbucket Cloud API token for a dedicated service account ([Atlassian instructions](https://support.atlassian.com/bitbucket-cloud/docs/create-a-repository-access-token/)), then connect it in Pixee's Bitbucket integration settings. You will provide three values: the service account's **username** (used for Git operations), its **email address** (used for API authentication — Bitbucket API tokens require email, not username), and the **API token** itself. The token needs six scopes: `read:user:bitbucket`, `read:workspace:bitbucket`, `read:repository:bitbucket`, `read:pullrequest:bitbucket`, `write:repository:bitbucket`, `write:pullrequest:bitbucket`. See [Bitbucket Integration → Authentication](/integrations/scms/bitbucket#authentication) for the full credential reference. For step-by-step install instructions, see the [installation guide](https://app.pixee.ai/docs/setup).

After connecting, choose which repositories Pixee should analyze -- all repositories in the workspace or specific repositories. Pixee analyzes the default branch (typically `main` or `master`) of each connected repository. You can customize branch targeting and other behavior later via a [PIXEE.yaml](/configuration/pixee-yaml) file in the repository root.

**Scanner integration (required):** Pixee needs scanner findings to generate fixes. Pixee natively integrates with 13 scanners. If your Bitbucket Pipelines include security scanner steps, Pixee can ingest findings from those pipeline runs. Any scanner producing SARIF output can also be connected through Pixee's [Integrations](/integrations/overview) page.

After setup, Pixee begins its initial analysis and opens pull requests for actionable findings within the first hour. If no PRs appear, verify API token permissions, workspace-level admin approval, and supported language coverage.

## What You'll See

When Pixee identifies a fixable vulnerability, it opens a standard Bitbucket pull request. Here is what the PR contains:

**PR title:** Describes the vulnerability type and location — for example, `Fix XSS vulnerability in TemplateRenderer.py`.

**PR description includes:**

| Section               | What It Contains                                                 |
| --------------------- | ---------------------------------------------------------------- |
| Vulnerability details | CVE or CWE reference, severity, and the scanner that detected it |
| Triage justification  | Why Pixee classified this as a true positive worth fixing        |
| Fix explanation       | What the code change does and why it resolves the vulnerability  |
| Quality scores        | Safety, effectiveness, and cleanliness ratings for the fix       |
| Diff                  | Standard Bitbucket diff showing 1-5 lines changed                |

**How to review:** Open the PR in Bitbucket and read the diff like any other pull request. Pixee fixes are typically 1-5 lines. No new dependencies are introduced unless the fix requires it.

**How to merge:** Standard Bitbucket merge flow. Merge commit, squash, or fast-forward — whatever your repository settings require. Pixee PRs respect your existing merge checks and required approvals.

**How to decline:** Decline the PR with a comment. Pixee does not reopen declined PRs for the same finding.

**Pipeline behavior:** Pixee-generated PRs trigger your existing Bitbucket Pipelines like any other pull request. If your pipeline includes security scans, tests, or linting steps, those run against the Pixee fix branch automatically.

For merge rate data, see [Security & Trust](/platform/security).

## What Data Leaves Your Network

Pixee's cloud SaaS deployment works as follows:

- **Code access.** Pixee reads repository contents through the API token's authorized access. Code is processed for analysis and is not stored after the analysis completes.
- **Scanner findings.** Pixee reads findings from connected scanners through pipeline results or direct integration. These findings are used to generate fixes.
- **PRs.** Pixee writes pull requests back to your Bitbucket workspace through the API. PR content (diffs, descriptions) lives in your Bitbucket instance.
- **No pipeline variables, no deployment settings, no SSH keys.** Pixee does not access Bitbucket Pipelines variables, deployment environments, or SSH key configurations.

For teams that require code to remain within their own infrastructure, Pixee offers [self-hosted deployment options](/enterprise/deployment) including embedded cluster, Helm / BYO Kubernetes, and air-gapped configurations.

## Bitbucket Data Center / Server

Bitbucket Server (formerly Data Center) is a separate Atlassian product from Bitbucket Cloud, with different credential and configuration mechanics. See [Bitbucket Integration → Bitbucket Server / Data Center](/integrations/scms/bitbucket#bitbucket-server--data-center) for the supported connection model and [Enterprise Deployment Options](/enterprise/deployment) for air-gapped and on-prem Pixee deployments.

## Jira Integration

If your team uses Jira alongside Bitbucket, Pixee PRs can reference Jira issue keys in their descriptions when configured. This allows Jira to automatically link the Pixee-generated PR to the relevant security issue, keeping your Atlassian workflow intact.

For Jira integration details, see [Integrations Overview](/integrations/overview).

