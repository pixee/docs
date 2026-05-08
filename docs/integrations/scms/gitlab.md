---
title: GitLab Integration
slug: /integrations/scms/gitlab
track: both
content_type: guide
seo_title: GitLab Integration with Pixee
description: Pixee integration with GitLab via service-account personal access token. Native merge request delivery with optional project-membership scoping.
sidebar_position: 4
---

# GitLab Integration

Pixee integrates with GitLab through a service-account personal access token, delivering automated security triage and remediation as merge requests. Developers review and merge Pixee fixes exactly like any other MR — zero new tools, zero new interfaces. The integration handles repository access, webhook events, and MR creation automatically. Works with GitLab.com and self-hosted GitLab.

> This page covers GitLab as a development platform. For GitLab SAST scanner integration, see [GitLab SAST](/integrations/scanners/gitlab-sast). For GitLab Dependency Scanning (SCA), see [GitLab SCA](/integrations/scanners/gitlab-sca).

## How Pixee Works with GitLab

Pixee connects to GitLab through a service-account personal access token (PAT) with the scopes required to read repositories, manage merge requests, and create fix branches.

**PAT-based authentication.** A single service-account PAT gives Pixee scoped access to your GitLab projects. The token's scopes are limited to what Pixee needs — full API access for MR management, repository read/write, and user-attribution metadata.

**Merge request delivery.** Every remediation Pixee generates arrives as a standard GitLab MR. MR descriptions include the finding context, fix explanation, triage justification, and confidence score. Developers see Pixee MRs in their MR queue alongside all other merge requests.

**Webhook events.** Pixee receives real-time events from your projects via GitLab webhooks. Repository changes, MR actions, and scanner output trigger Pixee's triage and remediation pipeline automatically.

**Project access control.** The `member_projects_only` toggle restricts Pixee to projects where the service account is an explicit member — a security control useful in large GitLab instances where you want Pixee scoped to a known subset of projects rather than every project the token can technically access.

## Authentication

The PAT requires the following scopes:

| Scope                   | Purpose                                                        |
| ----------------------- | -------------------------------------------------------------- |
| `api`                   | Full API access for MR creation and management                 |
| `read_user`             | Read user information for attribution                          |
| `read_repository`       | Read repository contents for analysis                          |
| `read_api`              | Read-only API access for discovery                             |
| `write_repository`      | Create fix branches and commit changes                         |
| `ai_features`           | Drive GitLab Duo / AI features used by the integration         |
| `read_registry`         | Read the project's container registry for image-based analyses |
| `read_virtual_registry` | Read GitLab's virtual dependency registry for SCA correlation  |

## Scanner Integration via GitLab

GitLab serves as both the development platform and a scanner delivery mechanism:

- **GitLab SAST findings** are ingested natively. See [GitLab SAST](/integrations/scanners/gitlab-sast).
- **GitLab Dependency Scanning** for SCA is ingested as well. See [GitLab SCA](/integrations/scanners/gitlab-sca).
- **Any SARIF scanner output** can be uploaded to Pixee from GitLab CI jobs.
- **Fortify + GitLab** is a documented enterprise deployment pattern. See [Fortify](/integrations/scanners/fortify).

## GitLab CI

Pixee works alongside existing GitLab CI/CD pipelines without requiring modifications. No changes to `.gitlab-ci.yml` are needed. Pixee is compatible with GitLab's security dashboard and vulnerability management features.

## Setup

1. **Create a service-account user** in GitLab with appropriate project membership. (Service accounts are recommended over personal accounts so the integration survives team-member departures.)
2. **Generate a personal access token** for the service account with the scopes listed above.
3. **Configure Pixee** with the PAT. For Pixee Enterprise (Helm), values live under `platform.scm.gitlab.{token, baseUri, webhookSecret}`. For SaaS, use the settings UI. For embedded-cluster Enterprise, the admin console exposes these fields under **Config → Development Platforms → GitLab**.
4. **Configure repository access** — either grant the service account access to all relevant projects, or use `member_projects_only` for explicit per-project membership.
5. **Pixee begins monitoring** projects, ingesting scanner findings, and generating remediation MRs.

For the install-time walkthrough, see [Getting Started with GitLab](/getting-started/gitlab).

### Webhook Configuration

For real-time event delivery from GitLab, configure a webhook on your project (or group) pointing at:

```
https://<your-pixee-server>/api/v1/integrations/gitlab-default/webhooks
```

The webhook secret you set in GitLab must match the `webhookSecret` configured in Pixee Enterprise. For setup instructions, see [GitLab's webhook documentation](https://docs.gitlab.com/user/project/integrations/webhooks/). Webhooks are optional — Pixee can still ingest findings via API polling — but recommended for low-latency response to scanner output.

## Self-Hosted GitLab

Pixee Enterprise Server connects to self-hosted GitLab via the same PAT integration used for GitLab.com. Capabilities are identical: MR delivery, webhook events, scanner ingestion, and project management all work the same way.

For self-hosted GitLab configuration, see the [enterprise deployment documentation](/enterprise/deployment).

See [Integrations Overview](/integrations/integrations-overview) for the full integration coverage matrix.
