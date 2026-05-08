---
title: GitLab Setup
slug: /getting-started/gitlab
track: dev
content_type: tutorial
seo_title: "Set Up Pixee for GitLab | Automated Security Merge Requests"
description: Install Pixee for GitLab to receive automated vulnerability triage and remediation as merge requests.
sidebar_position: 3
---

Install Pixee for GitLab to receive automated vulnerability triage and remediation as standard merge requests in your existing GitLab workflow. Connect your GitLab instance, select your projects, and Pixee begins delivering fixes that developers review and merge using the same MR process they already use. Works with GitLab SaaS and self-managed instances. No new interfaces, no separate dashboard.

## Prerequisites

Before you start, confirm the following:

- **GitLab permissions.** You need Maintainer or Owner role on the target projects. For group-level setup, you need Owner on the parent group.
- **GitLab instance.** GitLab SaaS (gitlab.com) or a self-managed GitLab instance. For self-managed, you will provide your instance URL during setup.
- **Supported language.** At least one project with code in Java, Python, JavaScript/TypeScript, .NET, Go, or PHP.
- **Scanner results (optional).** If you run GitLab SAST, Semgrep, Checkmarx, or other scanners through GitLab CI, Pixee can ingest those findings. This is additive — Pixee also runs its own analysis.

No agents to install. No runner configuration changes. No `.gitlab-ci.yml` edits needed to start.

## Setup

Create a GitLab personal access token for a dedicated service account, then connect it in Pixee's GitLab integration settings. The token needs `api`, `read_user`, `read_repository`, `read_api`, and `write_repository` scopes. See [GitLab Integration → Authentication](/integrations/scms/gitlab#authentication) for the full scope table and rationale, including the `member_projects_only` toggle. For step-by-step install instructions, see the [installation guide](https://app.pixee.ai/docs/setup).

After connecting, choose which GitLab projects Pixee should analyze -- all projects, member projects only, or specific projects. Pixee analyzes the default branch of each connected project. You can customize branch targeting and other behavior later via a [PIXEE.yaml](/configuration/pixee-yaml) file in the project root.

**Scanner integration:** Pixee natively integrates with 12 scanners. If your `.gitlab-ci.yml` includes the GitLab SAST template, Pixee ingests those findings directly. Third-party scanners producing SARIF output can be connected through Pixee's [Integrations](/integrations/overview) page. Pixee also runs its own analysis independently, so external scanners are additive, not required.

After setup, Pixee begins its initial analysis and opens merge requests for actionable findings within the first hour. If no MRs appear, verify PAT scopes, network connectivity (for self-managed instances), and supported language coverage.

## What You'll See

When Pixee identifies a fixable vulnerability, it opens a standard GitLab merge request. Here is what the MR contains:

**MR title:** Describes the vulnerability type and location — for example, `Fix path traversal in FileService.java`.

**MR description includes:**

| Section               | What It Contains                                                 |
| --------------------- | ---------------------------------------------------------------- |
| Vulnerability details | CVE or CWE reference, severity, and the scanner that detected it |
| Triage justification  | Why Pixee classified this as a true positive worth fixing        |
| Fix explanation       | What the code change does and why it resolves the vulnerability  |
| Quality scores        | Safety, effectiveness, and cleanliness ratings for the fix       |
| Diff                  | Standard GitLab diff showing 1-5 lines changed                   |

**How to review:** Read the diff like any other merge request. Pixee fixes are typically 1-5 lines. No new dependencies are introduced unless the fix requires it.

**How to merge:** Standard GitLab merge flow. If your project has merge request approval rules or CI pipeline requirements, Pixee MRs go through the same gates as any developer-authored MR.

**How to reject:** Close the MR with a comment. Pixee does not reopen closed MRs for the same finding.

**CI pipeline behavior:** Pixee-generated MRs trigger your existing GitLab CI pipeline like any other merge request. If your pipeline includes SAST, tests, or linting stages, those run against the Pixee fix branch automatically.

For merge rate data, see [Fix Safety](/how-it-works/fix-safety).

## What Data Leaves Your Network

Pixee's cloud SaaS deployment works as follows:

- **Code access.** Pixee reads repository contents through the personal access token's authorized API access. Code is processed for analysis and is not stored after the analysis completes.
- **Scanner findings.** Pixee reads findings from GitLab SAST reports or connected third-party scanners. These findings are used to generate fixes.
- **MRs.** Pixee writes merge requests back to your GitLab instance through the API. MR content (diffs, descriptions) lives in your GitLab instance.
- **No CI secrets, no variables, no deployment data.** Pixee does not access CI/CD variables, runner tokens, or deployment configurations.

For teams that require code to remain within their own infrastructure, Pixee offers [self-hosted deployment options](/enterprise/deployment) including embedded cluster, Helm / BYO Kubernetes, and air-gapped configurations.

## Self-Managed GitLab

Self-managed GitLab is supported. See [GitLab Integration → Self-Hosted GitLab](/integrations/scms/gitlab#self-hosted-gitlab) for the connection model and network requirements, and [Enterprise Deployment Options](/enterprise/deployment) for air-gapped and on-prem Pixee deployments.

## Frequently Asked Questions

### Does Pixee work with GitLab CI/CD?

Yes. Pixee-generated merge requests run through your existing GitLab CI pipeline like any other MR — including SAST stages, test suites, and approval rules. You can also configure Pixee to ingest scanner results produced by your CI pipeline.

### What scanners does Pixee support on GitLab?

Pixee natively integrates with 12 scanners including GitLab SAST, Semgrep, Checkmarx, Snyk Code, SonarQube, and any scanner producing SARIF output. Pixee triages findings from these scanners and generates fixes for confirmed vulnerabilities.

### Do I need to modify my `.gitlab-ci.yml` to use Pixee?

No. Pixee connects through a personal access token and operates independently of your CI pipeline configuration. No changes to `.gitlab-ci.yml` are required to start. If you want Pixee to ingest scanner results from your pipeline, that configuration is handled in the Pixee integration settings, not in your CI file.
