---
title: Bitbucket Integration
slug: /integrations/scms/bitbucket
track: both
content_type: guide
seo_title: Bitbucket Integration with Pixee
description: Pixee integration with Bitbucket via API token. Native pull request delivery and SARIF upload from Bitbucket Pipelines or any external CI system.
sidebar_position: 2
---

# Bitbucket Integration

Pixee integrates with Bitbucket Cloud through an API token, delivering automated security triage and remediation as pull requests. Developers review and merge Pixee fixes exactly like any other PR — zero new tools, zero new interfaces.

## How Pixee Works with Bitbucket

Pixee connects to Bitbucket Cloud using a workspace-scoped API token. API tokens are the current authentication method, replacing app passwords (deprecated by Atlassian).

**Pull request delivery.** Every remediation Pixee generates arrives as a standard Bitbucket PR. PR descriptions include the finding context, fix explanation, triage justification, and confidence score.

**Username plus email.** Bitbucket API tokens require both your account's **email address** (used for API authentication) and your **username** (used for Git operations). Configure both in Pixee — using just one will not work. We recommend using a dedicated service-account user rather than a personal user, so the integration survives team-member departures.

## Authentication

| Credential    | Purpose                                                               |
| ------------- | --------------------------------------------------------------------- |
| Username      | Git operations against the workspace's repositories                   |
| Email address | API authentication (Bitbucket API tokens require email, not username) |
| API token     | Authorizes the workspace operations defined by the scopes below       |

**Required API token scopes:**

| Scope                         | Purpose                                           |
| ----------------------------- | ------------------------------------------------- |
| `read:user:bitbucket`         | Identify the authenticated user                   |
| `read:workspace:bitbucket`    | Discover repositories in the workspace            |
| `read:repository:bitbucket`   | Read code for analysis                            |
| `read:pullrequest:bitbucket`  | Read PR state for ingestion and event correlation |
| `write:repository:bitbucket`  | Push fix branches                                 |
| `write:pullrequest:bitbucket` | Create and manage remediation PRs                 |

For instructions on creating an API token, see Atlassian's [Bitbucket Cloud documentation](https://support.atlassian.com/bitbucket-cloud/docs/create-a-repository-access-token/).

## Scanner Integration

Bitbucket Pipelines is one option for running scanners, but many teams use Jenkins, CircleCI, GitHub Actions, or other CI systems with Bitbucket-hosted repositories. Pixee works with all of them:

- **SARIF upload from Bitbucket Pipelines** — scanner steps in `bitbucket-pipelines.yml` can produce SARIF and upload it to Pixee.
- **SARIF upload from external CI** — Jenkins, CircleCI, GitHub Actions, or any CI system that produces SARIF can upload findings to Pixee.
- **All named scanner integrations** and the universal SARIF connector work with Bitbucket-hosted repositories.

## Setup

1. **Create a service-account user** in your Bitbucket workspace.
2. **Generate an API token** for the service account with the six scopes listed above.
3. **Configure Pixee** with the username, email address, and API token. For Pixee Enterprise (Helm), the values live under `platform.scm.bitbucket.{username, emailAddress, apiToken}`. For SaaS, use the settings UI. For embedded-cluster Enterprise, the admin console exposes these fields under **Config → Development Platforms → BitBucket**.
4. **Pixee begins monitoring** for scanner findings and generating remediation PRs.

For the install-time walkthrough, see [Getting Started with Bitbucket](/getting-started/bitbucket).

## Bitbucket Server / Data Center

Bitbucket Server (formerly Data Center) is a separate Atlassian product from Bitbucket Cloud. The integration mechanics — credentials, scopes, and configuration paths — differ. For Bitbucket Server deployments running on Pixee Enterprise, see the [enterprise deployment documentation](/enterprise/deployment) for the supported connection model and current configuration details.

See [Integrations Overview](/integrations/integrations-overview) for the full integration coverage matrix.
