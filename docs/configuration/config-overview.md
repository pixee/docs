---
title: Configuration Overview
slug: /configuration/overview
track: dev
content_type: guide
seo_title: Configuration Overview -- Pixee Docs
description: Configure Pixee behavior via PIXEE.yaml, organization settings, and AI settings. Covers repository management, scheduling, notifications, and reporting.
sidebar_position: 1
---

# Configuration Overview

Pixee is configurable at three levels: a PIXEE.yaml file in each repository for developer-controlled behavior, organization-wide settings in the Pixee dashboard for security team policies, and AI settings for tuning triage and remediation behavior. Most teams run Pixee with zero configuration on day one and customize as they scale. This section covers every configuration surface.

## Configuration Philosophy

Pixee works out of the box. The default settings enable Triage Automation and Remediation Automation for all supported languages and vulnerability types across your connected repositories. No PIXEE.yaml file, no dashboard toggles, no AI tuning required to start receiving pull requests with validated fixes.

Configuration exists for when defaults are not enough. Maybe your team wants to exclude a test directory, batch PRs into weekly review cycles, or route Slack notifications to a security channel. Pixee's configuration model is designed around progressive customization: start with zero config, then layer on settings as you understand your team's needs.

Two principles guide the model:

- **Developer agency.** PIXEE.yaml lives in the repository root, version-controlled alongside your code. Developers own the behavior of Pixee in their repos the same way they own `.eslintrc` or `dependabot.yml`.
- **Security team governance.** Organization-wide settings in the Pixee dashboard let security leads enforce policy across all repositories without touching individual repos.

## Configuration Layers

Pixee settings operate across three layers. When a setting is defined at multiple layers, the more specific layer takes precedence.

| Layer        | Scope             | Who Controls  | Mechanism               |
| ------------ | ----------------- | ------------- | ----------------------- |
| Repository   | Single repo       | Developers    | PIXEE.yaml in repo root |
| Organization | All repos         | Security team | Pixee dashboard         |
| AI Settings  | Analysis behavior | Security team | Pixee dashboard         |

**Precedence:** Repository-level PIXEE.yaml settings override organization defaults where applicable. Organization-level policies may restrict which PIXEE.yaml overrides are honored, giving security teams guardrails over developer-controlled configuration.

If a PIXEE.yaml file is invalid or contains syntax errors, Pixee falls back to organization defaults and logs a warning. No analysis is skipped.

## Quick Reference: What Goes Where

Use this table to jump to the right page for your configuration task.

| I want to...                                          | Go to                                                |
| ----------------------------------------------------- | ---------------------------------------------------- |
| Exclude specific files or directories from analysis   | [PIXEE.yaml Reference](/configuration/pixee-yaml)    |
| Ignore specific findings or CWE categories            | [PIXEE.yaml Reference](/configuration/pixee-yaml)    |
| Enable or disable specific fix types                  | [PIXEE.yaml Reference](/configuration/pixee-yaml)    |
| Customize PR formatting (labels, title prefix)        | [PIXEE.yaml Reference](/configuration/pixee-yaml)    |
| Add or remove repositories from monitoring            | [Repository Management](/configuration/repositories) |
| Organize repos by team or business unit               | [Repository Management](/configuration/repositories) |
| Set scan schedules or switch to on-demand analysis    | [Operations](/configuration/operations)              |
| Route notifications to Slack or email                 | [Notifications](/configuration/operations)           |
| Set up webhook integrations for custom workflows      | [Notifications](/configuration/operations)           |
| Manage team member access and roles                   | [Users & Access](/configuration/users)               |
| Configure SSO with your identity provider             | [Users & Access](/configuration/users)               |
| Tune AI triage sensitivity                            | [AI Settings](/configuration/ai-settings)            |
| Control which finding categories get AI-powered fixes | [AI Settings](/configuration/ai-settings)            |
| Configure reporting exports or dashboards             | [Reporting](/configuration/operations)               |
| Export data for compliance audits                     | [Reporting](/configuration/operations)               |

## Getting Started with Configuration

If you just installed Pixee, the recommended approach is:

1. **Week one: run with defaults.** Let Pixee analyze your repositories and open PRs with its default settings. Review the fixes, check the triage results, and get a feel for the baseline behavior.
2. **Week two: customize per-repo behavior.** Add a PIXEE.yaml file to repositories that need specific exclusions, ignored findings, or PR formatting preferences. See [PIXEE.yaml Reference](/configuration/pixee-yaml) for common recipes.
3. **Ongoing: tune organization settings.** As you scale to more repositories, use the Pixee dashboard to set organization-wide policies for scheduling, notifications, and AI behavior.

Enterprise self-hosted deployments have additional configuration surfaces for infrastructure (LLM providers, authentication, observability) managed through the admin console or Helm values. See [Enterprise > Deployment Options](/enterprise/deployment) for details.
