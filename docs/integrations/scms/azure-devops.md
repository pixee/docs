---
title: Azure DevOps Integration
slug: /integrations/scms/azure-devops
track: both
content_type: guide
seo_title: Azure DevOps Integration with Pixee
description: Pixee integration with Azure DevOps via personal access token and webhook configuration. Optional work-item linking for branch-policy compliance.
sidebar_position: 1
---

# Azure DevOps Integration

Pixee integrates with Azure DevOps through a personal access token and webhook configuration, delivering automated security triage and remediation as pull requests. Developers review and merge Pixee fixes exactly like any other PR — zero new tools, zero new interfaces. Optional work-item linking supports organizations that enforce "Require linked work item" branch policies. Works with Azure DevOps Services (cloud) and Azure DevOps Server (on-premises).

## How Pixee Works with Azure DevOps

Pixee connects to Azure DevOps using your organization name plus a personal access token (PAT) for API access. Optional webhook credentials authenticate inbound webhook requests from Azure DevOps to Pixee for real-time event delivery.

**PAT-based authentication.** A PAT with full _Code_ access handles repository reads, branch operations, and pull-request management. Use a custom scope rather than "Full access" so the token grants only what the integration needs.

**Pull request delivery.** Every remediation Pixee generates arrives as a standard Azure DevOps PR. PR descriptions include the finding context, fix explanation, triage justification, and confidence score.

**Webhook integration (optional).** Azure DevOps can deliver repository and PR events to Pixee for low-latency response to scanner output. Configure a webhook user and password in Pixee, then point Azure DevOps webhook deliveries at the Pixee endpoint with HTTP Basic auth using those credentials.

## Authentication

| Credential                         | Purpose                                                                                                                                 |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Organization name                  | Identifies your Azure DevOps organization to Pixee                                                                                      |
| Personal access token              | A PAT with **full _Code_ access** (custom scope, not "Full access"). Authorizes repository reads, branch operations, and PR management. |
| Webhook user / password (optional) | HTTP Basic credentials Pixee uses to authenticate inbound webhook requests from Azure DevOps                                            |

For Pixee Enterprise (Helm), these values live under `platform.scm.azure.{organization, token, webhook.user, webhook.password}`. For SaaS, use the settings UI. For embedded-cluster Enterprise, the admin console exposes these fields under **Config → Development Platforms → Azure DevOps**.

## Scanner Integration

Pixee works with any scanner that produces SARIF output run from Azure Pipelines or any external CI system. No modification to existing pipeline YAML is required. Scanner findings are uploaded to Pixee via SARIF; Pixee then triages and remediates them, delivering fix PRs into the same Azure DevOps repository where the code lives.

## Setup

1. **Create a personal access token** in Azure DevOps with a custom scope that includes full _Code_ access.
2. **(Optional) Choose webhook credentials** — a username and password that Pixee will use to authenticate inbound webhook requests from Azure DevOps.
3. **Configure Pixee** with your organization name, the PAT, and (optionally) the webhook credentials. See [Authentication](#authentication) above for the values map.
4. **(Optional) Set up Azure DevOps webhooks** to deliver repository and PR events to your Pixee endpoint, using HTTP Basic auth with the credentials from step 2.
5. **Pixee begins monitoring** for scanner findings and generating remediation PRs.

For the install-time walkthrough, see [Getting Started with Azure DevOps](/getting-started/azure-devops).

## Azure DevOps Server (On-Premises)

Pixee Enterprise Server supports both Azure DevOps Services (cloud) and Azure DevOps Server (on-premises) with the same capabilities. The same PAT and webhook integration model applies.

For on-premises configuration, see the [enterprise deployment documentation](/enterprise/deployment).

## FAQ

### Does Pixee work with Azure DevOps Server (on-premises)?

Yes. Pixee Enterprise Server connects to Azure DevOps Server via the same PAT plus webhook integration used for Azure DevOps Services.

### What permissions does the PAT need?

A custom scope with **full _Code_ access**. Avoid the "Full access" preset — that grants more than the integration needs.

### Are the webhook credentials required?

No, they are optional. Without them, Pixee operates against Azure DevOps without inbound webhook events. Configuring webhooks gives the integration lower-latency response to repository and PR events.

### Do I need Azure Pipelines?

No. Pixee works with any scanner that produces SARIF, regardless of where the scanner runs. Many teams use Azure Pipelines, but Jenkins or other CI systems work equally well.

See [Integrations Overview](/integrations/overview) for the full integration coverage matrix.
