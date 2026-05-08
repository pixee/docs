---
title: "Users & Access"
slug: /configuration/users
track: dev
content_type: guide
seo_title: "Users & Access -- Pixee Docs"
description: Manage user access, roles, and SSO integration in Pixee. Covers Admin, Security Lead, and Member roles.
sidebar_position: 6
---

# Users & Access

Pixee supports role-based access that aligns with how security and development teams already work. Security leads configure organization-wide policies and view triage results across all repositories. Developers interact with Pixee through PRs in their normal SCM workflow and can customize behavior per-repository via PIXEE.yaml. Enterprise deployments integrate with your corporate identity provider for SSO.

## Access Model Overview

Pixee has two interaction surfaces, each serving a different audience:

**SCM workflow (developers).** Developers never need a Pixee login for day-to-day use. Pixee delivers fixes as standard pull requests in GitHub, GitLab, Azure DevOps, or Bitbucket. Developers review and merge them using their existing tools, the same way they handle any other PR. Triage context is embedded in the PR description.

**Pixee dashboard (security team).** Security leads and admins use the Pixee dashboard to configure organization-wide policies, review triage results across all repositories, manage user access, and view reporting. The dashboard is where governance happens.

This separation means Pixee adds no new tools to developer workflows. Developers see PRs in their existing SCM. Security teams get a centralized policy and reporting surface.

## Roles and Permissions

Pixee uses three roles to control dashboard access:

| Role              | Capabilities                                                                                                                                              |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Admin**         | Full configuration access. Manage users, set organization policies, configure SCM connections, adjust AI settings, and view all repositories and reports. |
| **Security Lead** | View all repositories and triage results. Configure policies and notification routing. Cannot manage users or SCM connections.                            |
| **Member**        | View assigned repositories and their triage results. Interact with PRs in the SCM. Configure per-repository behavior via PIXEE.yaml.                      |

**How roles map to SCM permissions:** Pixee respects your SCM's access model. A developer who has write access to a repository in GitHub can merge Pixee PRs for that repository. Pixee dashboard roles control what users can do in the Pixee interface, not what they can do in the SCM.

**Principle of least privilege:** Assign the Admin role only to the team member responsible for Pixee administration. Use Security Lead for team members who need cross-repo visibility. Use Member for everyone else -- they interact with Pixee through PRs, not the dashboard.

## Inviting and Managing Users

### Adding team members

Invite users from the Pixee dashboard. Enter their email address and assign a role. The invited user receives an email with a link to set up their account.

### Managing existing users

From the dashboard, admins can:

- Change a user's role
- Revoke access (removes dashboard access immediately)
- View last login and activity

### Access revocation

When a user is removed from Pixee, their dashboard access is revoked immediately. Their SCM access is unaffected -- SCM permissions are managed by your SCM platform, not by Pixee.

## SSO and Identity Provider Integration

Pixee integrates with corporate identity providers for single sign-on:

| Provider               | Integration                      |
| ---------------------- | -------------------------------- |
| **Google Workspace**   | Direct login via Google OAuth    |
| **Microsoft Entra ID** | Direct login via Microsoft OAuth |
| **Okta**               | Direct login via Okta OIDC       |

SSO maps your identity provider's user accounts to Pixee roles. When a user authenticates through SSO, their Pixee role is determined by role mapping configured in the dashboard.

Enterprise self-hosted deployments also support embedded OIDC (via Authentik running in-cluster), which federates to your upstream corporate identity provider. This means SSO works even when Pixee runs inside your infrastructure with no external IdP dependency.

For full SSO configuration details on self-hosted deployments, see [Enterprise > Security Architecture](/enterprise/security-architecture).

