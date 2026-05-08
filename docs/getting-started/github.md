---
title: GitHub Setup
slug: /getting-started/github
track: dev
content_type: tutorial
seo_title: "Set Up Pixee for GitHub | Automated Security Fixes in PRs"
description: Install the Pixee GitHub App for automated vulnerability triage and remediation delivered as pull requests.
sidebar_position: 2
---

Install the Pixee GitHub App to receive automated vulnerability triage and remediation as standard pull requests in your existing repositories. Authorize the app, select which repositories to connect, and Pixee begins analyzing your code and scanner results immediately. Developers review and merge fixes the same way they handle any other PR. No CLI installs, no config files, no new dashboards.

## Prerequisites

Before you start, confirm the following:

- **GitHub permissions.** You need admin or owner permissions on the target repositories, or organization-level install permissions for org-wide deployment.
- **Supported language.** At least one repository with code in Java, Python, JavaScript/TypeScript, .NET, Go, or PHP.
- **Scanner results (required).** Pixee needs scanner findings to perform triage and generate fixes. If you already run CodeQL, Semgrep, Snyk Code, Checkmarx, SonarQube, or another scanner that uploads SARIF to GitHub Code Scanning, Pixee ingests those results automatically.

No agents to install. No CLI required. No configuration files needed to start.

## Setup

Install the Pixee GitHub App from the GitHub Marketplace, select your organization, and choose which repositories to connect. The app requests permissions for repository contents, pull requests, code scanning alerts, checks, webhooks, and metadata; it does not request access to secrets, environments, Actions workflows, or deployment configurations. See [GitHub Integration → Required Permissions](/integrations/scms/github#required-permissions) for the full table and rationale. For step-by-step install instructions, see the [installation guide](https://app.pixee.ai/docs/setup).

Pixee analyzes the default branch of each connected repository. Branch targeting and other behavior can be customized later via a [PIXEE.yaml](/configuration/pixee-yaml) file in the repository root.

**Scanner integration (required):** Pixee needs scanner findings to generate fixes. Pixee natively integrates with 13 scanners. If you use GitHub Code Scanning (which includes CodeQL, Semgrep via SARIF upload, and others), Pixee ingests those results automatically through the GitHub App. For scanners outside the GitHub Code Scanning ecosystem, connect them through Pixee's [Integrations](/integrations/integrations-overview) page.

After installation, Pixee begins its initial analysis. Within the first hour, Pixee opens pull requests for any actionable findings it identifies. If no PRs appear, the repository may have no actionable findings, or you may need to verify repository access and supported language coverage.

## Public Repositories Without an Existing Scanner

If you are setting up Pixee on a public GitHub repository that does not yet have a scanner configured, you can stand up the full pipeline in three steps using free tooling. CodeQL through GitHub Advanced Security (GHAS) and SonarQube Cloud are both free for public repositories.

### 1. Enable GitHub Issues for the dashboard view

Pixee can publish a status dashboard as a GitHub Issue in your repository. To enable it:

1. In your repository, go to **Settings → General**.
2. Under **Features**, check **Issues**.

You can disable Issues later if you prefer the Pixee dashboard at [app.pixee.ai](https://app.pixee.ai).

### 2. Connect a scanner

Pick either CodeQL via GHAS or SonarQube Cloud. Both are free for public repositories and integrate with Pixee through GitHub Code Scanning.

**Option A: CodeQL via GitHub Advanced Security**

1. In your repository, go to **Settings → Code security**.
2. Under **Tools → CodeQL analysis**, click **Set up**, then choose **Default**.
3. Wait for the first CodeQL run to finish. You can watch progress in the **Actions** tab.

For deeper detail on what Pixee extracts from CodeQL findings, see [CodeQL Integration](/integrations/scanners/codeql).

**Option B: SonarQube Cloud**

Follow the [SonarQube Cloud GitHub setup instructions](https://docs.sonarsource.com/sonarqube-cloud/getting-started/github/). Logging in with your GitHub identity is the simplest path. SonarQube Cloud is free for public repositories.

For Pixee's handling of SonarQube findings, see [SonarQube Integration](/integrations/scanners/sonarqube).

### 3. Install Pixeebot

Once the scanner has finished its first run:

1. Go to the [Pixeebot GitHub App page](https://github.com/apps/pixeebot/).
2. Click **Install** (or **Configure** if it is already installed) and follow the prompts.
3. After installation, you are redirected to the Pixee dashboard.

Pixee processes the scanner output for the default branch and, within a few minutes, opens pull requests for any actionable findings. If you enabled Issues in step 1, a Pixee status issue is also created with a summary of fixes available, in progress, and applied.

## What You'll See

When Pixee identifies a fixable vulnerability, it opens a standard GitHub pull request. Here is what the PR contains:

**PR title:** Describes the vulnerability type and location — for example, `Fix SQL injection in UserController.java`.

**PR description includes:**

| Section               | What It Contains                                                 |
| --------------------- | ---------------------------------------------------------------- |
| Vulnerability details | CVE or CWE reference, severity, and the scanner that detected it |
| Triage justification  | Why Pixee classified this as a true positive worth fixing        |
| Fix explanation       | What the code change does and why it resolves the vulnerability  |
| Quality scores        | Safety, effectiveness, and cleanliness ratings for the fix       |
| Diff                  | Standard GitHub diff showing 1-5 lines changed                   |

**How to review:** Read the diff like any other pull request. The fix is typically 1-5 lines. Pixee does not restructure your code or introduce new dependencies unless the fix requires it (for example, adding an input validation library).

**How to merge:** Standard GitHub merge flow. Squash, merge commit, or rebase — whatever your branch protection rules require.

**How to reject:** Close the PR with a comment. Pixee does not reopen closed PRs for the same finding.

For merge rate data, see [Security & Trust](/platform/security).

## What Data Leaves Your Network

Pixee's cloud SaaS deployment works as follows:

- **Code access.** Pixee reads repository contents through the GitHub App's authorized API access. Code is processed for analysis and is not stored after the analysis completes.
- **Scanner findings.** If you use GitHub Code Scanning, Pixee reads SARIF results through the Checks API. These findings are used to generate fixes.
- **PRs.** Pixee writes pull requests back to your repository through the GitHub API. PR content (diffs, descriptions) lives in your GitHub instance.
- **No secrets, no env vars, no deployment data.** Pixee does not access GitHub Actions secrets, environment variables, or deployment configurations.

For teams that require code to remain within their own infrastructure, Pixee offers [self-hosted deployment options](/enterprise/deployment) including embedded cluster, Helm / BYO Kubernetes, and air-gapped configurations.

## Repository Configuration

Pixee works with sensible defaults — no configuration file is needed to start. When you want to customize behavior, create a `PIXEE.yaml` file in the repository root.

Common customizations include:

- Excluding specific paths or files from analysis
- Adjusting which fix categories Pixee generates PRs for
- Configuring branch targeting

See the full [PIXEE.yaml Reference](/configuration/pixee-yaml) for all options.

## GitHub Enterprise Server (GHES)

GHES is supported via Pixee Enterprise (self-hosted) — not on the cloud SaaS. See [GitHub Integration → GitHub Enterprise Server](/integrations/scms/github#github-enterprise-server) for the connection model and network requirements, and [Enterprise Deployment Options](/enterprise/deployment) for infrastructure setup.

