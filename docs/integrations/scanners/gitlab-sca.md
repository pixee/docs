---
title: GitLab SCA Integration
slug: /integrations/scanners/gitlab-sca
track: both
content_type: guide
seo_title: GitLab Dependency Scanning (SCA) Integration with Pixee
description: Pixee integration with GitLab Dependency Scanning for automated triage and remediation of open-source dependency vulnerabilities.
sidebar_position: 8
---

# GitLab SCA Integration

Pixee integrates with GitLab Dependency Scanning (GitLab's built-in SCA) to triage findings and deliver remediation as merge requests. GitLab Dependency Scanning identifies known vulnerabilities in your project's open-source dependencies via the Gemnasium analyzer; Pixee classifies each finding by exploitability and opens MRs that bump dependency versions to fixed releases. Your GitLab Dependency Scanning configuration continues running exactly as it does today.

> "Dependency Scanning" is GitLab's name for SCA. The terms are interchangeable — `gemnasium-dependency_scanning` is the analyzer that produces the findings.

## What GitLab Dependency Scanning Detects

GitLab Dependency Scanning runs as part of CI/CD pipelines and surfaces known vulnerabilities (CVEs) in your project's direct and transitive dependencies. Coverage spans the major package ecosystems:

- **Java / JVM** — Maven, Gradle (`pom.xml`, `build.gradle`)
- **Python** — pip, Poetry, Pipenv (`requirements.txt`, `Pipfile.lock`, `poetry.lock`)
- **JavaScript / TypeScript** — npm, Yarn, pnpm (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`)
- **.NET** — NuGet (`packages.lock.json`)
- **Go** — Go modules (`go.sum`)
- **Ruby** — Bundler (`Gemfile.lock`)
- **PHP** — Composer (`composer.lock`)
- **Rust** — Cargo (`Cargo.lock`)
- **Conan** — C/C++ Conan packages

Findings are reported with CVE identifiers, severity, affected version ranges, and (where available) the version that fixes the vulnerability.

## How Pixee Enhances GitLab Dependency Scanning

### Triage

GitLab Dependency Scanning surfaces every CVE in every dependency — direct and transitive — without distinguishing whether the vulnerable code path is actually reachable in your project. The result is high finding volume, much of it not exploitable in context. Pixee's triage pipeline classifies each finding as TRUE_POSITIVE, FALSE_POSITIVE, or WONT_FIX based on whether the vulnerable function is actually called and reachable in your codebase.

This is the core SCA-noise problem: a CVE in a transitive dependency is only meaningful if your code (directly or via the dependency tree) actually exercises the vulnerable code path. Pixee's reachability analysis is what separates the small set of dependency CVEs that matter from the large set that do not.

Each finding is classified with code-level evidence — what calls the vulnerable function, what does not, and why.

### Remediation

GitLab shows dependency findings in the merge request security widget and vulnerability management dashboard but does not automatically open MRs to bump versions. Pixee closes this gap by delivering version-bump merge requests directly in GitLab for findings that are reachable and have a fixed version available.

Pixee's SCA remediation is deterministic: for each TRUE_POSITIVE with a fix available, Pixee opens an MR that updates the dependency to the lowest version in the fixed range, runs lockfile updates, and includes the CVE rationale in the MR description. Multi-vulnerability fixes can be batched per dependency to minimize MR churn.

For the full list of vulnerability types Pixee triages and fixes, see [What Pixee Fixes](/platform/what-pixee-fixes).

## Setup

1. **Connect GitLab to Pixee** — follow the [GitLab quick-start](/getting-started/source-control#gitlab) guide to install the Pixee integration.
2. **Ensure Dependency Scanning is enabled** — verify your `.gitlab-ci.yml` includes the `Dependency-Scanning.gitlab-ci.yml` template (or your own equivalent that runs `gemnasium-dependency_scanning`).
3. **Pixee ingests findings automatically** — when Dependency Scanning runs in your pipeline, Pixee receives the findings via the GitLab API.
4. **Review triage results and merge fixes** — Pixee opens MRs for remediable findings in your existing GitLab workflow.

**Prerequisites:** GitLab Ultimate license (Dependency Scanning is part of GitLab's Secure category, which requires Ultimate), Pixee GitLab integration installed.

See the [SCA](/platform/sca) page for details on how Pixee handles dependency findings end-to-end. See [Integrations Overview](/integrations/overview) for the full scanner coverage matrix.
