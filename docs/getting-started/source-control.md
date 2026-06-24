---
title: Connect Source Control
slug: /getting-started/source-control
track: dev
content_type: tutorial
seo_title: "Connect Source Control to Pixee | GitHub, GitLab, Azure DevOps, Bitbucket"
description: Connect your source control platform to Pixee. Quick-start summary for GitHub, GitLab, Azure DevOps, and Bitbucket with links to full setup guides.
sidebar_position: 2
---

Pixee delivers automated vulnerability fixes as pull requests (or merge requests) directly in your existing SCM workflow. Connect your SCM platform once, and Pixee starts triaging scanner findings and opening fix PRs. Setup takes under five minutes for most platforms.

Choose your platform below for the connection summary, then follow the link to the full setup guide for detailed instructions, permissions tables, and troubleshooting.

## GitHub

| Item                     | Detail                                                                                                                      |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------- |
| **Integration type**     | GitHub App (installed from GitHub Marketplace)                                                                              |
| **Required permissions** | Repository contents, pull requests, code scanning alerts, checks, webhooks, metadata                                        |
| **What you need**        | Admin or owner permissions on target repositories or org                                                                    |
| **Scanner ingestion**    | Automatic via GitHub Code Scanning (GHAS API) — no extra step if you run CodeQL, Semgrep, or other SARIF-uploading scanners |

**Quick steps:**

1. Install the Pixee GitHub App from the GitHub Marketplace and select your organization.
2. Choose which repositories to connect (org-wide or specific repos).
3. Pixee ingests scanner findings and opens fix PRs — typically within the first hour.

For public repositories without an existing scanner, see the [GitHub Setup guide](/integrations/scms/github) for a walkthrough using CodeQL (free for public repos).

**Full setup guide:** [GitHub Integration →](/integrations/scms/github)

---

## GitLab

| Item                    | Detail                                                                                                                         |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **Integration type**    | Personal access token (service account recommended)                                                                            |
| **Required scopes**     | `api`, `read_user`, `read_repository`, `read_api`, `write_repository`, `ai_features`, `read_registry`, `read_virtual_registry` |
| **What you need**       | Maintainer or Owner role on target projects; Owner on parent group for group-level setup                                       |
| **Instances supported** | GitLab SaaS (gitlab.com) and self-managed GitLab                                                                               |
| **Scanner ingestion**   | Automatic via GitLab Security Dashboard if you use GitLab SAST or other CI-integrated scanners                                 |

**Quick steps:**

1. Create a GitLab personal access token for a dedicated service account with the required scopes.
2. Connect the token in Pixee's GitLab integration settings, providing your instance URL (for self-managed).
3. Choose which projects Pixee should analyze (all, member-only, or specific).

**Full setup guide:** [GitLab Integration →](/integrations/scms/gitlab)

---

## Azure DevOps

| Item                    | Detail                                                                       |
| ----------------------- | ---------------------------------------------------------------------------- |
| **Integration type**    | Personal access token + optional webhook credentials                         |
| **Required scopes**     | Full **Code** access (not "Full access")                                     |
| **What you need**       | Project Administrator or Project Collection Administrator on target projects |
| **Instances supported** | Azure DevOps Services (dev.azure.com) and Azure DevOps Server (on-premises)  |
| **Scanner ingestion**   | Via Azure Pipelines scanner integrations; SARIF upload supported             |

**Quick steps:**

1. Create an Azure DevOps PAT for a dedicated service account with full Code access.
2. Connect the PAT and your organization name in Pixee's Azure DevOps integration settings.
3. Choose which projects and repositories to analyze.

**Full setup guide:** [Azure DevOps Integration →](/integrations/scms/azure-devops)

---

## Bitbucket

| Item                    | Detail                                                                                                                                                                    |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Integration type**    | API token (Bitbucket Cloud) or repository access token                                                                                                                    |
| **Required scopes**     | `read:user:bitbucket`, `read:workspace:bitbucket`, `read:repository:bitbucket`, `read:pullrequest:bitbucket`, `write:repository:bitbucket`, `write:pullrequest:bitbucket` |
| **What you need**       | Admin on the target workspace (Cloud) or Project Admin (Server)                                                                                                           |
| **Instances supported** | Bitbucket Cloud (bitbucket.org) and Bitbucket Data Center / Server                                                                                                        |
| **Credentials**         | Three values required: service account username, email address, and API token                                                                                             |
| **Scanner ingestion**   | Via Bitbucket Pipelines scanner steps; SARIF upload supported                                                                                                             |

**Quick steps:**

1. Create a Bitbucket Cloud API token for a dedicated service account.
2. Connect the token, username, and email address in Pixee's Bitbucket integration settings.
3. Choose which repositories in the workspace to analyze.

**Full setup guide:** [Bitbucket Integration →](/integrations/scms/bitbucket)

---

## After Connecting

Once your SCM platform is connected:

1. Pixee analyzes the default branch of each connected repository.
2. Scanner findings are ingested automatically (or via SARIF upload for scanners outside your SCM's native security surface).
3. Pixee opens fix pull requests for actionable findings — typically within the first hour.

**Next step:** [Your First Fix →](/getting-started/first-fix)

To customize behavior (branch targeting, severity filters, excluded paths), create a [PIXEE.yaml](/configuration/pixee-yaml) file in your repository root.

Need enterprise deployment (self-hosted, air-gapped, BYOM)? See [Enterprise Deployment Options](/enterprise/deployment).
