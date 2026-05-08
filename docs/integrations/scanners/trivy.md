---
title: Trivy Integration
slug: /integrations/scanners/trivy
track: both
content_type: guide
seo_title: Trivy Integration with Pixee
description: Pixee integration with Aqua Trivy for automated triage and remediation across container, dependency, IaC, and secret findings.
sidebar_position: 14
---

# Trivy Integration

Pixee integrates with Trivy to triage findings and deliver remediation as pull requests. Trivy's breadth — container images, dependencies, IaC, secrets — produces high-volume output. A single container base image can have hundreds of known CVEs, most of which are not exploitable in your application's context. Pixee's exploitability analysis classifies each finding so teams can focus on what is actually reachable and fixable. Trivy continues scanning as configured; Pixee adds the triage and fix layer it does not provide.

Trivy is Aqua Security's open-source scanner, widely adopted in cloud-native and DevSecOps environments.

## What Trivy Detects

- **Container image vulnerabilities** — OS packages and application dependencies
- **SCA** — open-source dependency vulnerabilities
- **Infrastructure as Code (IaC) misconfigurations** — Terraform, CloudFormation, Kubernetes manifests, Dockerfiles
- **Secret detection** — hardcoded credentials, API keys
- **License compliance issues**
- **SBOM generation** — CycloneDX and SPDX formats

Trivy produces SARIF output natively, making it highly interoperable with downstream tools.

## How Pixee Enhances Trivy

### Triage

Trivy's breadth is its strength and its challenge. Container image scans can surface hundreds of CVEs in OS packages, most of which are not exploitable in the application's context. Pixee's triage pipeline classifies each finding by exploitability and actionability, separating real threats from noise. For code-level findings and IaC misconfigurations, the triage engine investigates the actual codebase to determine whether the finding represents a real risk.

### Remediation

Trivy identifies vulnerabilities but does not generate code fixes. Pixee delivers fixes as pull requests — updating dependency versions, fixing IaC misconfigurations, and remediating code-level findings using both deterministic codemods and AI-powered generation.

For the full list of vulnerability types Pixee triages and fixes, see [What Pixee Fixes](/platform/what-pixee-fixes).

## Setup

1. **Install Pixee** for your platform — see [Connect Source Control](/getting-started/source-control) for GitHub, GitLab, Azure DevOps, and Bitbucket.
2. **Configure Trivy to output SARIF** — add `--format sarif` to your Trivy command or CI pipeline step.
3. **Upload SARIF to Pixee** — configure SARIF upload in your CI pipeline or use the Pixee integration endpoint.
4. **Review and merge** — Pixee triages findings and opens PRs for remediable issues.

**Prerequisites:** Trivy installed in your CI pipeline or locally, Pixee platform integration configured.

## FAQ

### Does Pixee work with Trivy's container image scanning?

Yes. Pixee ingests Trivy's SARIF output from container image scans and triages the findings by exploitability. For dependency vulnerabilities found in container images, Pixee can generate dependency update fixes where the dependency is managed in your source code.

### How does Pixee reduce noise from Trivy scans?

Trivy container scans often surface hundreds of CVEs in OS packages. Pixee's triage engine classifies each by exploitability — whether the vulnerable code path is actually reachable in your application — reducing the volume requiring human review.

### Does Trivy need to output SARIF for this integration?

Yes. Configure Trivy with `--format sarif` to produce SARIF output. Pixee also supports Trivy's native JSON format through the dedicated Trivy handler.

See [Integrations Overview](/integrations/overview) for the full scanner coverage matrix.
