---
title: "Integrations Overview & Coverage Matrix"
slug: /integrations/overview
track: both
content_type: guide
seo_title: "Pixee Integrations: Scanners, SCMs, and Universal SARIF"
description: Coverage matrix for Pixee integrations. 13 named scanners, 4 SCM platforms, and universal SARIF support.
sidebar_position: 1
---

# Integrations Overview & Coverage Matrix

Pixee integrations fall into two categories. **Scanning Tools** are the SAST, SCA, IAST, and aggregation platforms that produce findings — Pixee triages each finding and generates fixes. **Source Control** platforms are where Pixee delivers those fixes as pull requests or merge requests. Pixee does not replace your scanners or your SCM; it sits downstream of detection and inside your existing review workflow.

One triage-and-remediation pipeline spans every scanner in your stack, regardless of vendor. Pixee adds the resolution layer; the rest of your stack stays as it is.

## Source Control Coverage

Pixee delivers remediation as pull requests (or merge requests) on the four major development platforms. All four support cloud and self-hosted/on-premises deployments via Pixee Enterprise Server.

| Platform                                        | PR/MR Delivery        | Authentication        | Setup Guide                                  |
| ----------------------------------------------- | --------------------- | --------------------- | -------------------------------------------- |
| [GitHub](/integrations/scms/github)             | Native pull requests  | GitHub App            | [Get started](/getting-started/github)       |
| [GitLab](/integrations/scms/gitlab)             | Native merge requests | Personal access token | [Get started](/getting-started/gitlab)       |
| [Azure DevOps](/integrations/scms/azure-devops) | Native pull requests  | PAT + webhooks        | [Get started](/getting-started/azure-devops) |
| [Bitbucket](/integrations/scms/bitbucket)       | Native pull requests  | API token             | [Get started](/getting-started/bitbucket)    |

## Scanner Coverage Matrix

Pixee provides 13 named scanner integrations plus universal SARIF support for any other tool. Every scanner's findings flow through the same triage and remediation pipeline; the only difference is the depth of metadata extraction.

| Scanner                                                               | Integration Tier | Finding Types  | Triage | Remediation | Input Method     |
| --------------------------------------------------------------------- | ---------------- | -------------- | ------ | ----------- | ---------------- |
| [CodeQL](/integrations/scanners/codeql)                               | Deep             | SAST           | Yes    | Yes         | GHAS API / SARIF |
| [Semgrep](/integrations/scanners/semgrep)                             | Deep             | SAST           | Yes    | Yes         | SARIF            |
| [Checkmarx](/integrations/scanners/checkmarx)                         | Deep             | SAST           | Yes    | Yes         | SARIF            |
| [Veracode](/integrations/scanners/veracode)                           | Native           | SAST           | Yes    | Yes         | SARIF            |
| [Snyk Code](/integrations/scanners/snyk-code)                         | Native           | SAST           | Yes    | Yes         | SARIF            |
| [SonarQube / SonarCloud](/integrations/scanners/sonarqube)            | Native           | SAST           | Yes    | Yes         | SARIF            |
| [HCL AppScan](/integrations/scanners/appscan)                         | Native           | SAST           | Yes    | Yes         | SARIF            |
| [Polaris / Black Duck (Coverity)](/integrations/scanners/polaris)     | Native           | SAST           | Yes    | Yes         | SARIF            |
| [Fortify](/integrations/scanners/fortify)                             | Native           | SAST           | Yes    | Yes         | SARIF            |
| [Contrast Security](/integrations/scanners/contrast)                  | Native           | IAST           | Yes    | Yes         | SARIF            |
| [GitLab SAST](/integrations/scanners/gitlab-sast)                     | Native           | SAST           | Yes    | Yes         | GitLab API       |
| [GitLab SCA (Dependency Scanning)](/integrations/scanners/gitlab-sca) | Native           | SCA            | Yes    | Yes         | GitLab API       |
| [Trivy](/integrations/scanners/trivy)                                 | Native           | SAST, SCA, IaC | Yes    | Yes         | SARIF            |
| [DefectDojo](/integrations/scanners/defectdojo)                       | Aggregator       | Aggregated     | Yes    | Yes         | SARIF            |
| [Any SARIF-producing scanner](/integrations/sarif-universal)          | Universal        | Varies         | Yes    | Yes         | SARIF            |

**Integration tiers explained:**

- **Deep:** Dedicated handler with scanner-specific metadata extraction. Extracts dataflow paths, rule descriptions, and scanner-specific context for higher triage accuracy.
- **Native:** Recognized scanner with tool identification and standard SARIF processing. Findings are fully triaged and remediated through the standard pipeline.
- **Aggregator:** Vulnerability management platforms that consolidate findings from many scanners. Pixee adds triage and remediation on top.
- **Universal SARIF:** Any tool that produces SARIF output works automatically. No pre-built integration required.

All tiers feed into the same downstream triage and remediation pipeline. Deep integrations provide richer context; universal SARIF ensures no scanner is locked out.

## How Scanner Integration Works

Pixee's scanner integration follows a two-tier architecture that balances depth with breadth.

**Tier 1 — Native Handlers.** For the most widely deployed scanners, Pixee has dedicated handlers that extract scanner-specific metadata. Each handler understands the idiosyncrasies of that tool's SARIF output — where rule descriptions live, whether dataflow traces (codeFlows) are available, and what metadata the scanner includes or omits. Better metadata extraction means higher triage accuracy.

**Tier 2 — Universal SARIF.** For any scanner that produces SARIF (the OASIS standard for static analysis results), Pixee's universal SARIF engine ingests findings automatically. No pre-built integration required. The system dynamically adapts its handling strategy based on whatever metadata the SARIF contains.

Both tiers feed into the same downstream pipeline:

```
Scanner runs > SARIF output > Pixee ingests > Triage pipeline > TP / FP / WONT_FIX > Remediation PRs
```

The result: one triage and remediation pipeline across every scanner in your stack, from CodeQL to your internal proprietary scanner — all through the same workflow.

**Why SARIF matters.** SARIF (Static Analysis Results Interchange Format) is the OASIS open standard for static analysis results. Most modern SAST, SCA, and secret-scanning tools produce SARIF output natively or via converters. By standardizing on SARIF as the ingestion format, Pixee ensures that any scanner — commercial, open source, or proprietary — can feed into the triage and remediation pipeline without custom integration work.

**What this means in practice:**

- Internal or proprietary scanners that output SARIF work on day one
- New commercial scanners are supported immediately if they produce SARIF
- You are never locked to a specific tool list
- Adding or removing a scanner from your stack does not require any Pixee configuration changes

