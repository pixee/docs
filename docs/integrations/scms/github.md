---
title: GitHub Integration
slug: /integrations/scms/github
track: both
content_type: guide
seo_title: GitHub Platform Integration with Pixee
description: Pixee integration with GitHub via native GitHub App. Automated triage and remediation delivered as pull requests.
sidebar_position: 3
---

# GitHub Integration

Pixee integrates with GitHub through a native GitHub App that delivers automated security triage and remediation as pull requests. Developers review and merge Pixee fixes exactly like any other PR -- zero new tools, zero new interfaces. The GitHub App handles repository access, webhook events, and PR creation automatically. Works with GitHub.com and GitHub Enterprise Server.

> This page covers GitHub as a development platform. For CodeQL and GitHub Advanced Security scanner integration, see [CodeQL Integration](/integrations/scanners/codeql).

## How Pixee Works with GitHub

Pixee connects to GitHub through a first-class GitHub App -- the same integration model used by production-grade developer tools across the GitHub ecosystem.

**GitHub App integration.** A single GitHub App installation gives Pixee access to your organization's repositories. The app handles authentication, webhook events, and PR creation through GitHub's native API. Credentials are managed through the GitHub App's private key, with support for external secret managers (Vault, External Secrets Operator, SOPS) via `existingSecret` configuration.

**Pull request delivery.** Every remediation Pixee generates arrives as a standard GitHub pull request. PR descriptions include the finding context, fix explanation, triage justification, and confidence score. Developers see Pixee PRs in their PR queue alongside all other pull requests -- no separate dashboard, no new tool to learn.

**Webhook integration.** Pixee receives real-time events from your repositories via GitHub webhooks. Repository changes, PR actions, and scanner output trigger Pixee's triage and remediation pipeline automatically.

**Repository management.** Install the GitHub App on all repositories or select specific ones. Organization-level or repository-level installation gives administrators control over which repositories Pixee monitors.

## What Developers See

Fixes arrive as standard GitHub pull requests — no new tools, no new dashboards. Existing branch protection rules, required reviewers, and CI checks apply to Pixee PRs exactly as they would to any other PR. See [GitHub Setup → What You'll See](/getting-started/github#what-youll-see) for the full PR contents and review/merge/reject flow.

## Scanner Integration via GitHub

GitHub serves as both the development platform and a scanner delivery mechanism:

- **CodeQL findings via GHAS API:** Pixee's deep integration ingests CodeQL findings directly from GitHub Advanced Security. See [CodeQL Integration](/integrations/scanners/codeql) for details.
- **SARIF upload via GitHub Code Scanning:** Any scanner that uploads SARIF to GitHub's Code Scanning API makes those findings available to Pixee.
- **Direct SARIF upload from GitHub Actions:** Scanner results from Actions workflow jobs can be sent to Pixee directly.
- **All scanner findings** -- regardless of source -- are processed through the same triage and remediation pipeline.

## GitHub Actions Integration

Pixee works alongside your existing GitHub Actions workflows without requiring modifications.

Scanner results from Actions jobs are available to Pixee. If your CodeQL Action, Semgrep Action, or any SARIF-producing scanner runs in a GitHub Actions workflow, the output feeds into Pixee's pipeline automatically or via SARIF upload.

There is no need to modify existing `.github/workflows/` files. Pixee operates alongside your CI/CD pipeline, not inside it.

## Setup

1. **Install the Pixee GitHub App** on your organization or selected repositories.
2. **Authorize repository access** -- choose all repositories or select specific ones.
3. **Pixee begins monitoring** for scanner findings and generating remediation PRs.
4. **Configure preferences** in `PIXEE.yaml` (optional) to tune triage behavior and fix scope.
5. **Review and merge** your first Pixee PR.

For a detailed walkthrough, see [Getting Started with GitHub](/getting-started/github).

### Required Permissions

The Pixee GitHub App requests the following permissions during installation. Pixee Enterprise customers register a custom GitHub App and configure the same permissions; SaaS customers install the published Pixee App which carries these permissions pre-configured.

**Repository permissions:**

| Permission           | Access         | Purpose                                                       |
| -------------------- | -------------- | ------------------------------------------------------------- |
| Checks               | Read and write | Report triage and fix-validation status on PRs                |
| Code scanning alerts | Read and write | Ingest CodeQL and SARIF findings; report fix status           |
| Commit statuses      | Read and write | Reflect fix-pipeline state on commits                         |
| Contents             | Read and write | Read code for analysis; create fix branches                   |
| Dependabot alerts    | Read and write | Ingest SCA findings from Dependabot                           |
| Issues               | Read and write | Read referenced issues; comment with triage context           |
| Metadata             | Read-only      | Repository metadata for configuration                         |
| Pull Requests        | Read and write | Create and manage remediation PRs                             |
| Workflows            | Read and write | Inspect Actions workflow state for scanner-result correlation |

**Organization permissions:**

| Permission | Access    | Purpose                                  |
| ---------- | --------- | ---------------------------------------- |
| Members    | Read-only | Resolve PR-author identities for scoping |

**Account permissions:**

| Permission      | Access    | Purpose                                       |
| --------------- | --------- | --------------------------------------------- |
| Email addresses | Read-only | Author attribution on Pixee-generated commits |

**Webhook events the App subscribes to:** Code scanning alert, Check run, Create, Dependabot alert, Issue comment, Issues, Pull request, Pull request review, Pull request review comment, Pull request review thread, Push, Repository.

See [Integrations Overview](/integrations/integrations-overview) for the full scanner coverage matrix.

## GitHub Enterprise Server

GHES (and Pixee Enterprise on github.com) is supported by registering a **custom GitHub App** on your GitHub host. Pixee Enterprise then connects using that App's credentials. The mechanics are the same as a standard GitHub App; the install path differs because you control the App registration end-to-end.

### Registering the Custom GitHub App

In your GitHub host (github.com or your GHES instance), go to **Settings → Developer settings → GitHub Apps → New GitHub App**, then:

1. **GitHub App name.** Choose something unique to your org (e.g., `AcmePixeebotApp`). Save the name — Pixee Enterprise needs it.
2. **Homepage URL.** Anything works (e.g., `https://pixee.ai`). You can change this later.
3. **Callback URL.** Set to `https://<your-pixee-host>/api/auth/login`.
4. **Request user authorization (OAuth) during installation.** Check this box.
5. **Webhook → Active.** Check this box.
6. **Webhook URL.** Set to `https://<your-pixee-host>/github-event`.
7. **Webhook secret.** Set to a randomly generated value. Save it — Pixee Enterprise needs it.
8. **Permissions.** Configure the repository, organization, and account permissions exactly as listed in [Required Permissions](#required-permissions) above.
9. **Subscribe to events.** Check the events listed in [Required Permissions](#required-permissions) above.
10. **Where can this GitHub App be installed?** Start with **Only on this account**; you can broaden later.
11. **Create GitHub App.** Save the generated **App ID**.
12. **Generate a private key** from the App's settings page. Download the `.pem` file.

### Configuring Pixee Enterprise

Provide the App's credentials to your Pixee Enterprise installation:

- **Embedded cluster.** Admin console → **Config → Development Platforms → GitHub** → enter the App name, App ID, and upload the private key. For GHES, select **Custom domain** for the **GitHub domain** setting and enter your GHES hostname.
- **Helm.** Set the values under `platform.github`:
  ```yaml
  platform:
    github:
      appName: "<your custom GitHub app name>"
      appId: "<your custom GitHub app id>"
      appWebhookSecret: "<your webhook secret>"
      appPrivateKey: |
        -----BEGIN RSA PRIVATE KEY-----
        ...
        -----END RSA PRIVATE KEY-----
      # For GHES on a custom domain, set the URL:
      # url: "https://github.your-company.com"
  ```

### Network and Verification

- **Bidirectional reachability** is required between your GitHub host and the Pixee Enterprise deployment. GitHub sends webhook events to Pixee; Pixee makes API calls back to GitHub. For air-gapped environments, see [Enterprise Deployment Options](/enterprise/deployment).
- **Verify connectivity** by checking the App's event log under **Settings → Developer settings → GitHub Apps → Advanced**. Successful deliveries to the Pixee webhook URL confirm the integration is reachable end-to-end.

For deployment-model details (embedded cluster, Helm, air-gapped), see [Enterprise Deployment Options](/enterprise/deployment).

