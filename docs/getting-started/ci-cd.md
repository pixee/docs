---
title: CI/CD Integration
slug: /getting-started/ci-cd
track: dev
content_type: tutorial
seo_title: "Pixee CI/CD Integration | Automated Security Fixes in Your Pipeline"
description: How Pixee fits into a CI/CD pipeline. Covers SCM-driven ingestion, SARIF upload patterns, and platform-specific examples.
sidebar_position: 7
---

Pixee fits into your CI/CD pipeline without adding a runtime fix step. Scanners run as they always have; their findings are ingested by the Pixee platform via your SCM integration (or via a SARIF upload to the SCM's code-scanning API), and Pixee opens fix pull requests asynchronously. Your pipeline does not block on Pixee, and your existing scanner steps, build steps, and deployment gates are untouched.

## How Pixee Fits in Your Pipeline

```
[Build] → [Scan (SAST/SCA)] → [Deploy gate]
                ↓
       Findings ingested by Pixee (via SCM integration)
                ↓
     Triage + Fix PR opened on the repository (async)
```

Your scanner runs as it always has. Findings flow to Pixee through one of two paths:

- **SCM-native ingestion.** Pixee's GitHub App, GitLab integration, Azure DevOps integration, or Bitbucket connector reads scanner findings from the platform's code-scanning surface (GHAS Code Scanning, GitLab Security Dashboard, etc.). No additional CI step is required.
- **SARIF upload.** For scanners that don't write to the platform's code-scanning surface, upload SARIF to the SCM's code-scanning API as a CI step. Pixee then ingests it through the SCM integration like any other finding.

Pixee processes findings on the platform, not in your pipeline. Fix generation runs asynchronously and arrives as pull requests. Your existing branch protection rules, code review process, and CI checks apply to every Pixee PR exactly as they do to any human-authored change.

**Pipeline time impact:** Zero or one additional step. If your scanner already publishes to the SCM's code-scanning API, no Pixee-specific step is needed. If you upload SARIF as a separate CI step, that step typically runs in seconds.

## What Data Leaves Your Network

This is the question teams ask first, and the answer depends on your deployment model.

| Data Type               | SaaS (Cloud)                                        | Self-Hosted (Embedded Cluster / Helm)                      | Air-Gapped                                |
| ----------------------- | --------------------------------------------------- | ---------------------------------------------------------- | ----------------------------------------- |
| Scanner results (SARIF) | Sent to Pixee's service for triage                  | Stays in your cluster                                      | Stays in your network                     |
| Source code context     | Accessed via SCM integration (read-only)            | Stays in your cluster                                      | Stays in your network                     |
| Generated fixes         | Created on Pixee's infrastructure, delivered as PRs | Created and delivered within your cluster                  | Created and delivered within your network |
| LLM inference           | Pixee-managed                                       | Your chosen provider (OpenAI, Azure AI Foundry, Anthropic) | Customer-hosted LLM endpoint              |
| Telemetry               | Anonymized usage metrics (opt-out available)        | Configurable                                               | None                                      |

**SaaS deployment.** Pixee's service accesses your repositories through the SCM integration (GitHub App, GitLab PAT, etc.) with read-only code access and write access limited to creating PRs. Scanner results are transmitted for triage analysis. Source code is not stored after analysis completes.

**Self-hosted and air-gapped.** All data stays within your infrastructure. You control the LLM provider, the network boundary, and the storage. See [Enterprise Deployment Options](/enterprise/deployment) for embedded cluster, Helm, and air-gapped setup guides.

## Integration Comparison

| Platform                | Common Pattern                                                                                                                              | Setup Time | Prerequisites                                                                      |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ---------------------------------------------------------------------------------- |
| **GitHub Actions**      | Scanner publishes SARIF to GitHub Code Scanning; GHAS-native scanners (CodeQL) need no extra step                                           | ~5 min     | Pixee GitHub App installed ([setup guide](/getting-started/github))                |
| **GitLab CI**           | GitLab SAST + Dependency Scanning are ingested natively; external scanners upload SARIF to GitLab's vulnerability API                       | ~10 min    | GitLab integration configured ([setup guide](/getting-started/gitlab))             |
| **Azure Pipelines**     | Scanner runs in pipeline; SARIF is uploaded via Azure DevOps Code Scanning or directly to Pixee                                             | ~10 min    | Azure DevOps integration configured ([setup guide](/getting-started/azure-devops)) |
| **Bitbucket Pipelines** | Scanner runs in pipeline; SARIF is uploaded to Pixee                                                                                        | ~10 min    | Bitbucket connector configured ([setup guide](/getting-started/bitbucket))         |
| **Jenkins / other CI**  | Scanner runs anywhere; the SCM-native path still applies if your scanner publishes to GitHub Code Scanning, GitLab Security Dashboard, etc. | varies     | One of the four SCM integrations configured                                        |

Setup times are wall-clock time from "I have a pipeline" to "Pixee is processing scanner results." This does not include scanner setup — that is your existing infrastructure.

## GitHub Actions

Most teams add no Pixee-specific step. Scanners that publish to GitHub Code Scanning (CodeQL, Semgrep with the GitHub uploader, third-party scanners with `github/codeql-action/upload-sarif`) are ingested by Pixee through the GitHub App.

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Your existing scanner step.
      - name: Run CodeQL
        uses: github/codeql-action/analyze@v3
```

CodeQL writes findings directly to GitHub Code Scanning. Pixee's GitHub App reads them through the GHAS API and opens fix PRs.

For scanners that don't write to Code Scanning natively, upload the SARIF afterwards:

```yaml
- name: Run my scanner
  run: my-scanner --format sarif > results.sarif

- name: Upload SARIF to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

**Prerequisites:** Install the Pixee GitHub App ([GitHub Setup](/getting-started/github)).

## GitLab CI

GitLab SAST and Dependency Scanning are ingested natively — Pixee reads findings from GitLab's vulnerability API, no extra CI step is required:

```yaml
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml

stages:
  - build
  - test
  - scan
```

For external scanners, run them in CI and emit GitLab-compatible reports (or upload SARIF to GitLab's security dashboard via the security report artifacts). Pixee picks them up through the same GitLab integration.

**Prerequisites:** Configure the GitLab integration with a service-account PAT ([GitLab Setup](/getting-started/gitlab)).

**Self-hosted GitLab:** supported. Configure the custom base URI in the Pixee integration settings.

## Azure Pipelines

Run your scanner as a pipeline task and emit SARIF. The exact ingestion path depends on which scanner: scanners with Azure DevOps Code Scanning support publish there; others can upload SARIF directly to Pixee.

```yaml
trigger:
  - main

pool:
  vmImage: "ubuntu-latest"

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: "3.11"

  # Your existing scanner step.
  - script: |
      pip install semgrep
      semgrep --config auto --sarif -o $(Build.ArtifactStagingDirectory)/results.sarif .
    displayName: "Run Scanner"
```

After the scanner publishes results to your repository's code-scanning surface (or to Pixee directly), the Pixee Azure DevOps integration ingests them and opens fix PRs.

**Prerequisites:** Configure the Azure DevOps integration ([Azure DevOps Setup](/getting-started/azure-devops)).

**Work-item linking:** If your organization requires linked work items on PRs, configure the work item ID in the Pixee integration settings.

## Bitbucket Pipelines

Run your scanner as a pipeline step and emit SARIF. Pixee's Bitbucket connector ingests SARIF results uploaded via the connector's reporting endpoint.

```yaml
pipelines:
  default:
    - step:
        name: Build and Test
        script:
          - npm install
          - npm test

    - step:
        name: Security Scan
        script:
          - pip install semgrep
          - semgrep --config auto --sarif -o results.sarif .
        artifacts:
          - results.sarif
```

After the scan step, the SARIF file is available to the Pixee Bitbucket connector. Configuration of the upload step depends on your scanner — check the per-scanner integration page for specifics.

**Prerequisites:** Configure the Bitbucket connector ([Bitbucket Setup](/getting-started/bitbucket)). Supports Bitbucket Cloud and Bitbucket Server.

## Jenkins and Other CI Systems

Pixee does not require a specific CI system. As long as the scanner can run _somewhere_ in your CI and findings reach the Pixee platform via one of the four SCM integrations, the rest of the pipeline is unchanged.

Two common patterns:

1. **Scanner writes to the SCM's code-scanning surface.** A Jenkins job runs the scanner, then uploads SARIF to GitHub Code Scanning / GitLab Security Dashboard / etc. via that platform's API. Pixee picks up the findings through the SCM integration.
2. **Scripted upload to Pixee.** A pipeline step uploads SARIF directly to the Pixee API. The [Pixee CLI](/getting-started/cli)'s `pixee api` subcommand can POST a SARIF body, or you can use any HTTP client.

```bash
# Example: upload SARIF directly to Pixee using the CLI in any CI environment.
brew tap pixee/pixee && brew install pixee   # one-time, on a runner with brew
export PIXEE_TOKEN="$PIXEE_TOKEN"
export PIXEE_SERVER="https://pixee.example.com"

pixee api /api/v1/scans \
  --method POST \
  --input results.sarif
```

Discover the exact upload endpoint for your deployment via HAL link traversal: `pixee api /api/v1` lists the available resources, and each resource's `_links` lead to its upload routes.

**Prerequisites:** A Pixee API token (`PIXEE_TOKEN`) and the deployment URL (`PIXEE_SERVER`). For background on the CLI, see [Pixee CLI](/getting-started/cli).

## Scanner Result Ingestion

Pixee accepts scanner results through three paths:

1. **SCM-native APIs.** GitHub Code Scanning, GitLab vulnerability reports, Azure DevOps Code Scanning, Bitbucket reports. Pixee reads findings through the SCM integration.
2. **Direct SARIF upload to Pixee.** Use the [Pixee CLI](/getting-started/cli) (`pixee api`) or an HTTP client. Useful when your CI system doesn't have a clean upload path to the SCM.
3. **Native scanner integrations.** For 13 named scanners (CodeQL, Semgrep, Checkmarx, Veracode, Snyk Code, SonarQube, AppScan, Polaris, Fortify, Contrast, GitLab SAST, GitLab SCA, Trivy) Pixee uses dedicated handlers that extract scanner-specific metadata for richer triage. See the per-scanner pages under [Integrations](/integrations/overview).

**Universal SARIF.** Any SARIF 2.1.0–producing scanner works through the universal SARIF integration. See [Universal SARIF Integration](/integrations/sarif-universal).

## Troubleshooting

**Scanner findings not reaching Pixee.** Verify the SCM integration's read access to code-scanning results. For GitHub, confirm the App has `code_scanning_alerts: read`. For GitLab, confirm the PAT has `read_api`. For Azure DevOps and Bitbucket, confirm the credentials authorize reading the security/reports endpoints.

**SARIF parsing errors.** Confirm the SARIF file conforms to SARIF 2.1.0 and is valid JSON. Most scanner export options include a SARIF format flag — check your scanner's documentation.

**Fix PRs not appearing.** Check that the Pixee integration has write access to the target repository. For GitHub, the App needs `pull_requests: write`. Fix generation is asynchronous — allow a few minutes after findings are ingested.

**`pixee api` returns exit code 2.** Authentication failed. Run `pixee auth status` to confirm the configured server and token, or reset both with `pixee auth login`. See [Pixee CLI](/getting-started/cli) for credential resolution rules.

## Frequently Asked Questions

### Does adding Pixee require a new pipeline step?

Not always. If your scanner writes to the SCM's code-scanning surface (GHAS, GitLab vulnerability reports, etc.), Pixee ingests findings through the SCM integration with no pipeline change. A new step is only required when uploading SARIF directly to Pixee or to the SCM's code-scanning API.

### Does Pixee slow down my CI/CD pipeline?

No. Pixee processes findings on the platform asynchronously, not in your pipeline. The pipeline itself sees only the time to invoke any SARIF upload step (seconds), not the time to generate fixes.

### Does Pixee require code changes to my application?

No code changes to your application. You configure the SCM integration once; pipeline definition files are unchanged or gain a single SARIF upload step depending on your scanner.

### Can I control which findings Pixee fixes?

Yes. Use [PIXEE.yaml](/configuration/pixee-yaml) to configure which finding types, languages, or severity levels Pixee should address. You can also scope fixes to specific directories or exclude paths.

### Where does the `pixee` CLI fit?

The CLI is a client for the Pixee REST API — useful for managing workflows, querying scan history, or scripting SARIF uploads. It does not run scanners or generate fixes locally. See [Pixee CLI](/getting-started/cli).
