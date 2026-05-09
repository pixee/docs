---
title: FAQ
slug: /faq/general
track: both
content_type: faq
seo_title: "Pixee FAQ | General, Enterprise, and Troubleshooting"
description: "Common questions about Pixee: how it works, safety, enterprise deployment, and troubleshooting."
sidebar_position: 1
---

Frequently asked questions organized by topic. For detailed technical documentation, follow the links in each answer.

## General

### What is automated vulnerability remediation?

Automated vulnerability remediation programmatically fixes security findings without requiring a developer to manually write the patch. Pixee generates fixes as pull requests that go through your existing review and CI/CD pipeline. Fixes come from two sources: deterministic codemods — rule-based transformations where the same input always produces the same output — and constrained AI generation for patterns where deterministic rules do not reach. Every fix passes a multi-layer validation pipeline before delivery. The typical fix changes 1-5 lines of code, applying established OWASP/SANS security patterns.

### How does automated vulnerability triage work?

Pixee's triage engine routes each finding through three progressive tiers: deterministic analyzers for known patterns (sub-second, zero cost), AI agents for ambiguous cases (dynamic codebase investigation), and automatic handling for novel and custom rule types — including proprietary scanners and custom rulesets — without manual configuration. Every verdict includes a structured justification — the specific code paths, security controls, or context that drove the decision. Up to 98% false positive reduction. See [Triage](/platform/triage) for the full architecture.

### What is a codemod?

A codemod is a deterministic code transformation rule that rewrites source code from a vulnerable pattern to a safe pattern. Same input, same output — no randomness, no variation between runs. Pixee's open-source codemod engines (codemodder-java, codemodder-python) are publicly inspectable. See [Codemodder](/open-source/codemodder) for the full catalog.

### What scanners does Pixee work with?

Pixee integrates natively with a growing list of scanners including CodeQL, Semgrep, Checkmarx, Veracode, Snyk Code, SonarQube, AppScan, Polaris, Fortify, Contrast, GitLab SAST, GitLab SCA, and Trivy. Any scanner that produces SARIF output can also connect through the Universal SARIF integration — over 50 additional scanners validated. You do not need to change your detection stack.

### Does Pixee replace my existing scanners?

No. Pixee sits downstream of your existing SAST, SCA, and DAST tools. It consumes their findings, triages them to separate real threats from false positives, and produces validated fixes for confirmed vulnerabilities.

### What programming languages does Pixee support?

Java, Python, JavaScript/TypeScript, .NET/C#, Go, Ruby, PHP, Kotlin, Rust, Scala, Swift, plus IaC formats (Terraform, Dockerfile, K8s/Helm, CloudFormation). Deterministic codemod coverage is deepest for Java and Python. See [Language Support](/languages/overview) for the full coverage matrix.

### Does Pixee support SCA (software composition analysis) remediation?

Yes. SCA findings flow through the same triage and remediation pipeline as SAST findings. Pixee handles transitive dependency resolution, breaking change detection, and dependency upgrade coordination — delivering atomic PRs that include both the manifest version bump and downstream source-file changes. See [SCA](/platform/sca) for details.

### What is the difference between Pixee and GitHub Copilot Autofix?

Copilot Autofix is limited to GitHub Advanced Security (CodeQL) findings on GitHub. Pixee works with a growing list of natively integrated scanners across GitHub, GitLab, Azure DevOps, and Bitbucket. Pixee also provides triage automation, which Copilot Autofix does not offer. Pixee uses deterministic codemods alongside constrained AI, while Copilot Autofix relies on general-purpose AI code generation. Pixee also supports self-hosted and air-gapped deployment with Bring Your Own Model (BYOM).

### How long does it take to set up Pixee?

Cloud SaaS setup: install the GitHub App, GitLab integration, Azure DevOps extension, or Bitbucket connector and Pixee begins analyzing repositories immediately — under 5 minutes. Self-hosted deployment (embedded cluster or Helm) typically completes in under one hour. Air-gapped deployment takes longer due to private LLM configuration and image transfer.

### Does Pixee require code changes to install?

No. Pixee installs as a platform integration and requires zero code changes, CLI installs, or configuration files to start. Developers interact with Pixee through standard pull requests in their existing platform.

### How long does it take to see results?

Most teams see their first automated fix within hours of connecting a scanner with existing findings. Triage results appear even faster — Pixee begins classifying findings as soon as scanner data is available.

### Can I customize which vulnerabilities Pixee fixes?

Yes. PIXEE.yaml configuration lets you control which finding types Pixee addresses, which repositories are active, and what approval workflows apply. You can exclude specific files, directories, or finding categories. See the [PIXEE.yaml Reference](/configuration/pixee-yaml) for configuration syntax.

## Safety and Trust

### Does automated remediation break existing code?

Every fix goes through a multi-layer validation pipeline — constrained generation, independent evaluation by a separate model scoring Safety, Effectiveness, and Cleanliness, and your existing CI/CD pipeline and code review process. Fixes that do not pass validation are not delivered. See [Security & Trust](/platform/security).

### What is the merge rate for Pixee-generated fixes?

76% of Pixee-generated fixes are merged by development teams after human review on production deployments. This reflects developer trust after reviewing pre-validated fixes — not raw AI output. Fixes that cannot pass quality standards are suppressed before reaching a PR.

### What happens if an automated fix introduces a bug?

Every Pixee fix is delivered as a pull request, not a direct commit. Standard `git revert` applies if a merged change needs to be undone. There is no runtime dependency on Pixee for previously merged code. Closing an unmerged PR discards the proposed change with zero impact.

### How does Pixee handle false positives from scanners?

The triage engine reduces false positives by evaluating dataflow quality, detecting security controls between source and sink, classifying production vs. test code, and filtering intentionally-vulnerable projects. Each classification includes a structured justification. Security engineers can override any verdict. See [Triage](/platform/triage).

### Is automated vulnerability remediation safe for production code?

Yes. Pixee's fixes are narrow-scope security changes (1-5 lines) applying established OWASP/SANS patterns, not general-purpose code generation. They pass multi-layer validation before reaching a PR, and your existing CI/CD, SAST re-scanning, and code review gates all apply. The PR-only delivery model is an architectural constraint — there is no mode that allows direct commits. See [Security & Trust](/platform/security).

## Enterprise

### Does Pixee support self-hosted deployment?

Yes. Three deployment models: embedded cluster (turnkey, no Kubernetes expertise required), Helm (for existing Kubernetes infrastructure), and air-gapped (fully disconnected with customer-hosted LLM). See [Deployment Options](/enterprise/deployment).

### What are the infrastructure requirements for self-hosted Pixee?

Minimum: 8 vCPU, 32 GB RAM, 100 GB SSD (single Linux VM for embedded cluster). See [Deployment Options](/enterprise/deployment) for sizing guidance per model.

### Does Pixee support multiple SCM platforms simultaneously?

Yes. A single Pixee Enterprise deployment supports GitHub, GitLab, Azure DevOps, and Bitbucket at the same time. Each SCM connection is configured independently.

### Can Pixee run in an air-gapped environment?

Yes. Pixee supports fully air-gapped deployment with a customer-hosted LLM. No code leaves your environment after installation. License validation requires a network path to Pixee servers (direct or via proxy). See [Air-Gapped Deployment](/enterprise/air-gap).

### How does Pixee handle data residency requirements?

Self-hosted deployments keep all data in your network. Air-gapped deployments have zero outbound data transmission. For cloud SaaS, contact Pixee for data handling details. See [Security Architecture](/enterprise/security-architecture) for the full data flow table by deployment model.

### What data does Pixee send to LLM providers?

Only code snippets relevant to the specific vulnerability — the vulnerable function and surrounding context — are sent to the configured LLM provider. No repository names, organizational metadata, or CI/CD configuration is sent. In self-hosted and air-gapped deployments, this traffic stays within your network. Bring Your Own Model (BYOM) means you control the provider, the model, and the endpoint.

### Can I control which LLM provider Pixee uses?

Yes. BYOM supports OpenAI, Azure AI Foundry, Anthropic, and Azure Anthropic. For air-gapped deployments, you host the model entirely within your network. See [BYOM Configuration](/enterprise/byom).

### Does Pixee support SOC 2, FedRAMP, HIPAA, and other compliance frameworks?

Pixee's architecture supports the controls required for major compliance frameworks. Contact Pixee for current SOC 2 Type II certification status and audit report availability. See [Compliance](/enterprise/compliance) for the full framework mapping table covering SOC 2, HIPAA, FedRAMP, PCI-DSS, NIST 800-53, and ISO 27001.

### What audit trail does Pixee provide?

Every Pixee fix creates a defensible audit record: typed triage verdict with code-level evidence, fix quality scores on every PR, full Git history showing what changed when and why, SAST re-scanning confirmation, and developer approval recorded in the merge event. Triage decisions export via CSV, JSON, and API. See [Compliance](/enterprise/compliance).

### How does Pixee handle AI governance requirements?

Every AI-generated fix passes through documented validation layers before delivery — constrained generation, independent evaluation by a separate model, and your existing code review process. The PR-based workflow ensures human-in-the-loop approval for every change. A significant portion of fixes use zero LLM involvement (deterministic codemods). All decisions are auditable with persisted reasoning. See [Security & Trust](/platform/security) for the Responsible AI governance Q&A.

## Troubleshooting

### Why is Pixee not analyzing my repository?

Most likely cause: the repository has not been enabled in Pixee's settings after installing the SCM app.

1. Verify the GitHub App, GitLab integration, Azure DevOps extension, or Bitbucket connector is installed on the correct organization.
2. Check that the specific repository is enabled in Pixee's repository management settings — installing the app does not automatically enable all repositories.
3. Verify Pixee has the required permissions: read code, read pull requests, write pull requests.
4. For GitLab, confirm the service account has the required scopes (`api`, `read_user`, `read_repository`, `read_api`, `write_repository`).
5. For Azure DevOps, verify the PAT is active and the webhook is configured.

### Pixee installed but I do not see any activity. What is wrong?

Most likely cause: no scanner findings exist for the connected repository. **Connecting a scanner is required** — Pixee needs scanner findings to generate fixes and triage results.

1. Connect at least one scanner. See the [Integrations Overview](/integrations/overview) for setup instructions.
2. Verify the scanner has produced findings for the repository.
3. For custom or unsupported scanners, verify findings are in SARIF format and are being uploaded correctly.

### Why are scanner findings not showing up in Pixee?

Three common causes, in order of likelihood:

1. **Integration not configured.** Each scanner requires its own integration configuration.
2. **Format mismatch.** Scanner output does not match the expected specification. Verify SARIF compliance for custom scanners.
3. **Upload path incorrect.** Scanner results are not being delivered to the correct endpoint. Check the integration documentation for the expected delivery method.

### Scanner findings appear in Pixee but no fixes are generated. Why?

Not all findings have available fixes. Pixee generates fixes when: a codemod or AI generation path exists for the vulnerability pattern, the code context is sufficient for safe fix generation, and the fix passes the multi-layer validation pipeline. Findings without available fixes still receive triage classification. Check [Language Support](/languages/overview) for coverage of your specific finding types.

### Why is Pixee not opening PRs on my repository?

Check in order:

1. Repository enabled and Pixee has write PR permissions.
2. Scanner findings exist for the repository.
3. Fixes are available for the finding types present.
4. PIXEE.yaml is not excluding the relevant files, directories, or finding types.
5. Scheduling configuration has not deferred PR creation to a future window.

If all five check out, contact Pixee support with your repository name and the finding types you expect fixes for.

### A Pixee PR failed CI. What should I do?

**If the failure is in Pixee's fix:** Close the PR. Pixee's fixes are validated before delivery, but they cannot account for every CI environment configuration. Closing a PR with zero impact is the intended workflow for fixes that do not fit your context.

**If the failure is unrelated to Pixee's change:** Re-run CI. Check whether the CI failure also appears on other PRs to confirm it is not Pixee-specific.

### Why does Pixee classify a finding as false positive when I think it is real?

Review the structured justification provided with the classification — the specific code paths, security controls, or context signals that drove the decision. If you disagree after reviewing the evidence, override it. Overrides help calibrate triage accuracy for your codebase over time.

### How do I prevent Pixee from fixing certain vulnerability types?

Use [PIXEE.yaml](/configuration/pixee-yaml) to exclude specific finding types, files, or directories. You can also disable specific codemods by ID.

### How do I export triage decisions for compliance reporting?

Pixee exports triage decisions via CSV, JSON, and API. Each export includes timestamp, finding metadata, classification, structured justification, and any analyst overrides. See the [Reporting](/configuration/operations) page for export procedures.

### Can I use Pixee with a private or internal GitHub Enterprise instance?

Yes, with self-hosted deployment. Pixee Enterprise (embedded cluster, Helm, or air-gapped) runs within your network and connects to your internal SCM instance. See [Deployment Options](/enterprise/deployment).
