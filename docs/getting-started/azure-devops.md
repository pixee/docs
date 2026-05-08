---
title: Azure DevOps Setup
slug: /getting-started/azure-devops
track: dev
content_type: tutorial
seo_title: "Set Up Pixee for Azure DevOps | Automated Security PRs"
description: Install Pixee for Azure DevOps to receive automated vulnerability triage and remediation as pull requests in Azure Repos.
sidebar_position: 4
---

Install Pixee for Azure DevOps to receive automated vulnerability triage and remediation as standard pull requests in Azure Repos. Connect your Azure DevOps organization, select your projects, and Pixee begins delivering fixes that developers review and complete using the same PR workflow they already use. Works with Azure Pipelines for CI/CD integration. No new tools, no separate interface to learn.

## Prerequisites

Before you start, confirm the following:

- **Azure DevOps permissions.** You need Project Administrator or Project Collection Administrator permissions on the target projects. Organization-level settings may require Organization Administrator access.
- **Azure DevOps instance.** Azure DevOps Services (cloud, dev.azure.com) or Azure DevOps Server (on-premises). For on-premises, see [Azure DevOps Server (On-Premises)](#azure-devops-server-on-premises) below.
- **Supported language.** At least one repository in Azure Repos with code in Java, Python, JavaScript/TypeScript, .NET, Go, or PHP.
- **Scanner results (required).** Pixee needs scanner findings to perform triage and generate fixes. If you run scanners through Azure Pipelines (CodeQL, Checkmarx, SonarQube, or others), Pixee can ingest those results.

No extensions to install from the Visual Studio Marketplace. No pipeline YAML changes needed to start.

## Setup

Create an Azure DevOps personal access token for a dedicated service account with a custom scope that includes full _Code_ access (not "Full access" — that grants more than needed). Connect it in Pixee's Azure DevOps integration settings, along with your organization name. Webhook user/password credentials are optional and enable real-time event delivery. See [Azure DevOps Integration → Authentication](/integrations/scms/azure-devops#authentication) for the full credential reference. For step-by-step install instructions, see the [installation guide](https://app.pixee.ai/docs/setup).

After connecting, choose which projects and repositories Pixee should analyze -- at the organization, project, or individual repository level. Pixee targets the default branch of each connected repository. You can customize branch targeting and other behavior later via a [PIXEE.yaml](/configuration/pixee-yaml) file in the repository root.

**Scanner integration (required):** Pixee needs scanner findings to generate fixes. Pixee natively integrates with 13 scanners. If your Azure Pipelines run security scanners, Pixee can ingest findings from those pipeline runs. Any scanner producing SARIF output can also be connected through Pixee's [Integrations](/integrations/overview) page.

After setup, Pixee begins its initial analysis and opens pull requests for actionable findings within the first hour. If no PRs appear, verify PAT scopes, organization-level admin consent, and supported language coverage.

## What You'll See

When Pixee identifies a fixable vulnerability, it opens a standard pull request in Azure Repos. Here is what the PR contains:

**PR title:** Describes the vulnerability type and location — for example, `Fix insecure deserialization in ApiHandler.cs`.

**PR description includes:**

| Section               | What It Contains                                                 |
| --------------------- | ---------------------------------------------------------------- |
| Vulnerability details | CVE or CWE reference, severity, and the scanner that detected it |
| Triage justification  | Why Pixee classified this as a true positive worth fixing        |
| Fix explanation       | What the code change does and why it resolves the vulnerability  |
| Quality scores        | Safety, effectiveness, and cleanliness ratings for the fix       |
| Linked work items     | Work item reference if configured during setup                   |
| Diff                  | Standard Azure Repos diff showing 1-5 lines changed              |

**How to review:** Open the PR in Azure Repos and read the diff like any other pull request. Pixee fixes are typically 1-5 lines.

**How to complete:** Standard Azure DevOps completion flow — approve, set merge type (merge, squash, rebase), and complete. Pixee PRs respect your existing branch policies, required reviewers, and build validation pipelines.

**How to abandon:** Abandon the PR with a comment. Pixee does not recreate abandoned PRs for the same finding.

**Build validation:** Pixee-generated PRs trigger your existing Azure Pipelines build validation policies like any other PR. If your branch policies require a successful build before completion, the Pixee fix branch goes through the same gates.

For merge rate data, see [Security & Trust](/platform/security).

## What Data Leaves Your Network

Pixee's cloud SaaS deployment works as follows:

- **Code access.** Pixee reads repository contents through the personal access token's authorized API access. Code is processed for analysis and is not stored after the analysis completes.
- **Scanner findings.** Pixee reads findings from connected scanners through pipeline results or direct integration. These findings are used to generate fixes.
- **PRs.** Pixee writes pull requests back to Azure Repos through the API. PR content (diffs, descriptions) lives in your Azure DevOps instance.
- **No pipeline secrets, no service connections, no deployment data.** Pixee does not access Azure Pipelines variable groups, service connections, key vaults, or deployment gate configurations.

For teams that require code to remain within their own infrastructure, Pixee offers [self-hosted deployment options](/enterprise/deployment) including embedded cluster, Helm / BYO Kubernetes, and air-gapped configurations.

## Azure DevOps Server (On-Premises)

Azure DevOps Server is supported. See [Azure DevOps Integration → Azure DevOps Server (On-Premises)](/integrations/scms/azure-devops#azure-devops-server-on-premises) for the connection model and Entra ID notes, and [Enterprise Deployment Options](/enterprise/deployment) for air-gapped and on-prem Pixee deployments.

