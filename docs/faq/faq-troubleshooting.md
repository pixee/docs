---
title: Troubleshooting FAQ
slug: /faq/troubleshooting
track: both
content_type: faq
seo_title: Troubleshooting FAQ -- Pixee Docs
description: "Troubleshooting common Pixee issues: setup problems, scanner connectivity, PRs not appearing, CI failures, and triage questions."
sidebar_position: 3
---

This page covers the most common issues users encounter with Pixee: setup problems, scanner connectivity, PRs not appearing, fixes failing CI, and configuration questions. Each answer provides the most likely cause and step-by-step resolution. For enterprise deployment issues (Helm, air-gapped, embedded cluster), see [Enterprise Troubleshooting](/enterprise/troubleshooting). For product capability questions, see the [General FAQ](/faq/general).

## Setup and Installation

### Why is Pixee not analyzing my repository?

Most likely cause: the repository has not been enabled in Pixee's settings after installing the SCM app. Pixee supports 4 platforms (GitHub, GitLab, Azure DevOps, Bitbucket), and each requires platform-specific configuration.

1. Verify the GitHub App, GitLab integration, Azure DevOps extension, or Bitbucket connector is installed on the correct organization.
2. Check that the specific repository is enabled in Pixee's repository management settings — installing the app does not automatically enable all repositories.
3. Verify Pixee has the required permissions: read code, read pull requests, write pull requests.
4. For GitLab, confirm the service account has the required scopes (`api`, `read_user`, `read_repository`, `read_api`, `write_repository`).
5. For Azure DevOps, verify the PAT is active and the webhook is configured.

If all steps check out, see the [Getting Started](/) guide for platform-specific setup.

### How do I verify Pixee is installed correctly?

Check three things in order:

1. The SCM app or integration appears in your platform's installed apps list (GitHub Settings > Applications, GitLab Admin > Applications, etc.).
2. Pixee shows the repository in its dashboard with a connected status.
3. Pixee has opened at least one PR or triage result within 24 hours of connecting a repository with existing scanner findings.

If none of these are true, reinstall the integration following the [Getting Started](/) guide for your platform.

### Pixee installed but I do not see any activity. What is wrong?

Most likely cause: no scanner findings exist for the connected repository. Pixee needs scanner findings to generate fixes and triage results — if no scanner is connected or no findings exist, Pixee has nothing to act on. This is the most common misunderstanding during initial setup.

1. Connect at least one scanner. Pixee integrates natively with 12 scanners (CodeQL, Semgrep, Checkmarx, Veracode, Snyk Code, SonarQube, AppScan, Polaris, GitLab SAST, Trivy, DefectDojo, Fortify). See the [Integrations Overview](/integrations/overview).
2. Verify the scanner has produced findings for the repository. No findings means no triage results and no fixes.
3. For custom or unsupported scanners, check that findings are in SARIF 2.1.0 format and are being uploaded correctly.

Pixee begins analyzing findings as soon as scanner data is available. Most teams see their first results within hours.

### Can I use Pixee with a private or internal GitHub Enterprise instance?

Yes, with self-hosted deployment. Pixee Enterprise (embedded cluster, Helm, or air-gapped) runs within your network and connects to your internal SCM instance. Cloud SaaS connects to GitHub.com, GitLab.com, Azure DevOps, and Bitbucket Cloud. See [Deployment Options](/enterprise/deployment) for self-hosted setup.

## Scanner Connection Issues

### Why are scanner findings not showing up in Pixee?

Three common causes, in order of likelihood:

1. **Integration not configured.** The scanner has not been set up in Pixee's settings. Each scanner requires its own integration configuration — check the integration page for your specific scanner.
2. **Format mismatch.** Scanner output does not match the expected specification. For native integrations, verify the scanner version is compatible. For custom scanners, verify SARIF 2.1.0 compliance.
3. **Upload path incorrect.** Scanner results are not being delivered to the correct endpoint or location. Check the integration documentation for the expected delivery method (webhook, file upload, API).

### Pixee is showing findings from one scanner but not another. Why?

Each of the 12 natively supported scanners requires its own integration configuration. Verify for the missing scanner:

1. It is listed as connected in Pixee's integration settings.
2. It is producing output in the expected format.
3. Results are being delivered to the correct location.
4. It is not excluded by a rule in PIXEE.yaml.

Some scanners require explicit enablement in [PIXEE.yaml](/configuration/pixee-yaml). See the [Integrations Overview](/integrations/overview) for per-scanner setup requirements.

### My scanner findings appear in Pixee but no fixes are generated. Why?

Not all findings have available fixes. Pixee generates fixes when three conditions are met:

1. A codemod or AI generation path exists for the vulnerability pattern (see [Codemodder](/open-source/codemodder) for supported patterns).
2. The code context is sufficient for safe fix generation.
3. The fix passes the multi-layer validation pipeline.

Findings without available fixes still receive triage classification — Pixee will still tell you whether the finding is a true positive, false positive, or won't-fix. Check the [Language Support](/languages/overview) pages for coverage of your specific finding types.

### How do I connect a scanner that is not in Pixee's supported list?

Any scanner that produces SARIF 2.1.0 output can connect to Pixee via the Universal SARIF integration. Convert your scanner's output to SARIF format and upload it to Pixee. Pixee is scanner-agnostic — it generates fixes and triage classifications regardless of which scanner produced the finding. See the [Universal SARIF](/integrations/sarif-universal) page for format requirements and upload methods.

## PR and Fix Issues

### Why is Pixee not opening PRs on my repository?

Check in order:

1. **Repository enabled and permissions set.** Pixee has write PR permissions for the repository.
2. **Scanner findings exist.** At least one scanner has produced findings for the repository.
3. **Fixes available.** Codemods or AI generation paths exist for the finding types present (not all finding types have available fixes).
4. **Configuration not blocking.** PIXEE.yaml is not excluding the relevant files, directories, or finding types.
5. **Scheduling not delaying.** Scheduling configuration has not deferred PR creation to a future window.

If all five check out, contact Pixee support with your repository name and the finding types you expect fixes for.

### Pixee opened a PR but it failed CI. What should I do?

Review the CI failure and distinguish between two scenarios:

**If the failure is in Pixee's fix** -- the change breaks a test or introduces a build error -- close the PR. Pixee's fixes are validated before delivery through a multi-layer pipeline, but they cannot account for every CI environment configuration. Some fixes require adjustment for specific environments. Closing a PR with zero impact is the intended workflow for fixes that do not fit your context.

**If the failure is unrelated to Pixee's change** — a pre-existing flaky test, infrastructure issue, or unrelated build break — re-run CI. The fix itself may be correct. Check whether the CI failure also appears on other PRs to confirm it is not Pixee-specific.

### A Pixee fix does not match our code style. Can I adjust this?

Pixee's deterministic codemods follow standard language conventions. If your team uses specific formatting rules, your existing linters and formatters (Prettier, Black, google-java-format, etc.) will reformat the fix when CI runs. Pixee's fix is functionally correct — it addresses the security vulnerability with established OWASP/SANS patterns, typically in 1-5 lines. Formatting is handled by your existing toolchain as part of the standard PR pipeline. This is the same workflow you use for any other code change — the fix arrives as a PR and your formatting tools apply automatically.

### How do I prevent Pixee from fixing certain types of vulnerabilities?

Use [PIXEE.yaml](/configuration/pixee-yaml) to exclude specific finding types, files, or directories. You can also disable specific codemods by ID. This gives you granular control over what Pixee addresses without disabling it entirely. Common use cases: excluding test directories, deferring certain vulnerability categories to manual review, or limiting Pixee to specific repositories during a phased rollout. See the [PIXEE.yaml Reference](/configuration/pixee-yaml) for configuration syntax and examples.

### A Pixee PR conflicts with another PR. How do I resolve this?

Pixee PRs are standard Git pull requests. Resolve conflicts the same way you would for any other PR: rebase, merge the conflicting PR first, or close the Pixee PR. If you close the PR, Pixee will re-analyze the repository and open a new PR with updated context on its next analysis run.

## Triage Issues

### Why does Pixee classify a finding as false positive when I think it is real?

Pixee's triage classification includes the reasoning behind every decision — the specific code paths, security controls, or context signals that drove the classification. Review the structured justification provided with the classification. Common reasons Pixee classifies a finding as false positive include: an upstream sanitizer or security control the scanner missed, the vulnerable code is unreachable from any application entry point, or untrusted data does not actually flow to the vulnerable function. If you disagree with the classification after reviewing the evidence, override it. Pixee surfaces the reasoning precisely so your team can make the final call. Overrides help calibrate triage accuracy for your specific codebase context over time.

### Triage results are not appearing for some findings. Why?

Triage requires sufficient code context to perform reachability and data-flow analysis. If the finding metadata from your scanner does not include enough context — file path, line number, rule ID — triage may not produce a classification. Verify your scanner output includes complete finding metadata. For custom SARIF scanners, ensure the `results` array includes `locations` with `physicalLocation` data. Pixee's triage engine significantly reduces findings requiring manual review when scanner metadata is complete.

### How do I export triage decisions for compliance reporting?

Pixee exports triage decisions via CSV, JSON, and API. Each export includes timestamp, finding metadata, classification (true positive / false positive / won't-fix), structured LLM justification, and any analyst overrides. For GRC platform integration, use the API for automated evidence collection. See the [Reporting](/configuration/operations) page for export procedures, format details, and integration examples.
