---
title: GitLab SAST Integration
slug: /integrations/scanners/gitlab-sast
track: both
content_type: guide
seo_title: GitLab SAST Integration with Pixee
description: Pixee integration with GitLab SAST for automated triage and remediation of findings from multiple analyzers.
sidebar_position: 7
---

# GitLab SAST Integration

Pixee integrates with GitLab SAST to triage findings from GitLab's built-in static analysis and deliver remediation as merge requests. GitLab SAST uses multiple underlying analyzers (Semgrep, SpotBugs, Gosec, Bandit, and others), each with different false positive rates and metadata quality. Pixee normalizes these heterogeneous findings into a single triage workflow and generates fixes that GitLab SAST does not provide. Your GitLab SAST configuration continues running exactly as it does today.

## What GitLab SAST Detects

GitLab SAST is the built-in SAST capability in GitLab Ultimate. It runs as part of CI/CD pipelines using a collection of open-source analyzers orchestrated by GitLab's framework:

- OWASP Top 10 and common injection flaws via Semgrep (multi-language)
- Java vulnerabilities via SpotBugs
- Go vulnerabilities via Gosec
- Python vulnerabilities via Bandit
- Ruby vulnerabilities via Brakeman
- JavaScript/TypeScript vulnerabilities via NodeJsScan
- Security misconfigurations across frameworks

## How Pixee Enhances GitLab SAST

### Triage

GitLab SAST aggregates findings from multiple analyzers, each with different severity scales, rule naming conventions, and false positive rates. Pixee's triage pipeline normalizes these findings into consistent classifications with structured justifications.

This solves a specific problem: teams using GitLab SAST receive findings from 5+ different analyzers with inconsistent metadata quality. Pixee applies the same exploitability analysis regardless of which underlying analyzer produced the finding, providing a unified view of what is real and what is noise.

Each finding is classified as TRUE_POSITIVE, FALSE_POSITIVE, or WONT_FIX with code-level evidence.

### Remediation

GitLab shows SAST findings in the merge request security widget and vulnerability management dashboard but does not generate automated code fixes. Pixee closes this gap by delivering fixes as merge requests directly in GitLab.

GitLab SAST findings often lack the contextual detail needed for efficient manual remediation. Pixee's fix generation adds the missing context — vulnerability explanation, fix rationale, and quality scores — directly in the MR.

For the full list of vulnerability types Pixee triages and fixes, see [What Pixee Fixes](/platform/what-pixee-fixes).

## Setup

1. **Connect GitLab to Pixee** — follow the [GitLab quick-start](/getting-started/source-control#gitlab) guide to install the Pixee integration
2. **Ensure GitLab SAST is enabled** — GitLab SAST runs via CI/CD pipeline templates. Verify your `.gitlab-ci.yml` includes the SAST template
3. **Pixee ingests findings automatically** — when GitLab SAST runs in your pipeline, Pixee receives the findings via the GitLab API
4. **Review triage results and merge fixes** — Pixee opens MRs for remediable findings in your existing GitLab workflow

**Prerequisites:** GitLab Ultimate license (for SAST), Pixee GitLab integration installed

See [Integrations Overview](/integrations/overview) for the full scanner coverage matrix.
