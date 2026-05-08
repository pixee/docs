---
title: General FAQ
slug: /faq/general
track: both
content_type: faq
seo_title: General FAQ -- Pixee Docs
description: "Common questions about Pixee: how automated triage and remediation work, fix safety, merge rates, and getting started."
sidebar_position: 1
---

This page answers the questions we hear most from security leaders, security engineers, and developers evaluating automated vulnerability remediation. Every answer draws from production data and customer experience. If your question is not here, check the [Enterprise Technical FAQ](/faq/enterprise) for deployment and compliance questions or the [Troubleshooting FAQ](/faq/troubleshooting) for operational issues.

## How It Works

### What is automated vulnerability remediation?

Automated vulnerability remediation is the process of programmatically fixing security findings without requiring a developer to manually write the patch. Pixee generates fixes as pull requests that go through your existing review and CI/CD pipeline. Fixes are created using two approaches: deterministic codemods -- rule-based transformations where the same input always produces the same output -- and constrained AI generation for patterns where deterministic rules do not reach. Every fix passes a multi-layer validation pipeline before delivery. Nothing reaches a developer that has not been independently evaluated for safety, effectiveness, and cleanliness. The typical fix changes 1-5 lines of code, applying established OWASP/SANS security patterns rather than generating novel logic. See [Codemodder](/open-source/codemodder) for the full codemod catalog.

### How does automated vulnerability triage work?

Automated triage analyzes scanner findings for exploitability and contextual relevance before any human review. Pixee's triage engine uses reachability analysis (can an attacker reach the vulnerable code?), data-flow analysis (does untrusted data flow to the vulnerability?), and context signals (is there an upstream security control the scanner missed?) to classify findings as true positive, false positive, or won't-fix. Every classification includes a structured justification — not a confidence score, but an auditable investigation trail. This significantly reduces the volume of findings requiring manual review. See [Triage Engine](/how-it-works/triage-engine) for production metrics.

### What is the difference between vulnerability detection and remediation?

Detection tools (SAST, SCA, DAST) find potential security issues. Remediation tools fix them. Most organizations have invested heavily in detection but still fix vulnerabilities manually. Pixee automates the remediation step, turning scanner output into merged fixes.

### What is a codemod?

A codemod is a deterministic code transformation rule that rewrites source code from a vulnerable pattern to a safe pattern. "Deterministic" means the same input always produces the same output -- no randomness, no variation between runs. Pixee ships codemods across Java, Python, JavaScript/TypeScript, .NET, Go, and PHP. Codemods handle the predictable fix patterns (SQL injection parameterization, XSS output encoding, insecure API replacement). Constrained AI generation handles the patterns where deterministic rules cannot reach. See [Codemodder](/open-source/codemodder) for the full catalog.

### What scanners does Pixee work with?

Pixee integrates natively with 12 scanners: CodeQL, Semgrep, Checkmarx, Veracode, Snyk Code, SonarQube, AppScan, Polaris, GitLab SAST, Trivy, DefectDojo, and Fortify. Any scanner that produces SARIF output can also connect through the Universal SARIF integration. Pixee is scanner-agnostic — it consumes findings from your existing tools and generates fixes regardless of which scanner identified the issue. You do not need to change your detection stack.

### Does Pixee replace my existing scanners?

No. Pixee sits downstream of your existing SAST, SCA, and DAST tools. It consumes their findings, triages them to separate real threats from false positives, and produces validated fixes for confirmed vulnerabilities.

## Safety and Trust

### Does automated remediation break existing code?

Every fix goes through a multi-layer validation pipeline -- constrained generation that limits what the AI can modify, independent evaluation by a separate model that scores safety, effectiveness, and cleanliness, and your existing CI/CD pipeline and code review process. Fixes that do not pass validation are not delivered. Nothing is merged without developer approval. See [Fix Safety](/how-it-works/fix-safety) for production metrics.

### How accurate are AI-generated security fixes?

Pixee uses constrained AI generation, not free-form code suggestion. The AI operates within defined transformation boundaries -- it can modify the vulnerability pattern but cannot restructure surrounding code. Most fixes apply established OWASP/SANS remediation patterns to SAST-identified issues, typically changing 1-5 lines. A separate AI evaluator -- running as a distinct inference call, not self-critique from the same model -- independently scores every fix on safety, effectiveness, and cleanliness before delivery. Fixes that fail evaluation are automatically rejected and never shown to users. The constraint is deliberate: narrow scope means lower risk. See [Fix Safety](/how-it-works/fix-safety) for production metrics.

### What happens if an automated fix introduces a bug?

Every Pixee fix is delivered as a pull request, not a direct commit. There is no mode, setting, or override that allows Pixee to commit directly to a branch. The fix runs through your existing CI/CD pipeline — tests, linters, build checks — before any human sees it. If CI fails, the developer sees the failure and rejects the PR. If CI passes but the developer identifies an issue during review, they reject or modify the PR like any other code change. Standard `git revert` applies if a merged change needs to be undone. There is no runtime dependency on Pixee for previously merged code — if you removed Pixee entirely, all merged fixes remain as standard code in your repository. Closing an unmerged PR discards the proposed change with zero impact. Pixee never bypasses your existing quality gates.

### What is a good merge rate for automated security fixes?

Merge rate is the percentage of automated pull requests that developers merge after human review. This metric spans all supported languages, fix types, and customer environments. Individual teams may see higher or lower rates depending on their review cadence and codebase complexity. See [Fix Safety](/how-it-works/fix-safety) for production metrics.

### How does Pixee handle false positives from scanners?

Pixee's triage engine reduces false positives before fixes are generated. It uses reachability analysis (can an attacker reach the vulnerable code?), data-flow analysis (does untrusted data flow to the vulnerability?), and context signals (is there an upstream sanitizer or security control the scanner missed?) to classify findings. Each classification includes a structured justification — the specific code paths and evidence that drove the decision, not just a confidence score. Findings classified as false positives are surfaced with this reasoning so your team can validate the classification and override if they disagree. A significant portion of findings that would have required manual triage can be automatically classified. See [Triage Engine](/how-it-works/triage-engine) for production metrics on false positive reduction.

### Is automated vulnerability remediation safe for production code?

Yes, when implemented with proper guardrails. Pixee's safety model has three layers: constrained generation that limits what the AI can modify to established OWASP/SANS security patterns, independent evaluation where a separate model scores every fix on safety, effectiveness, and cleanliness before delivery, and your existing code review and CI/CD pipeline. Deterministic codemods use zero LLM involvement -- zero hallucination risk on those fixes. Fixes that use AI pass independent evaluation before reaching a PR. The same SAST tools that found the original vulnerability also scan the proposed fix; if the fix introduces new findings, those appear in the PR. No fix touches production without developer approval. This is fundamentally different from general-purpose AI code generation where the user is the sole quality gate. See [Fix Safety](/how-it-works/fix-safety) for production metrics.

## Getting Started and Adoption

### How long does it take to set up Pixee?

Cloud SaaS setup takes minutes: install the GitHub App, GitLab integration, Azure DevOps extension, or Bitbucket connector and Pixee begins analyzing your repositories immediately. No code changes, no SDK, no CI/CD modifications. Self-hosted deployment — either the turnkey embedded cluster (single Linux VM with 8 vCPU, 32 GB RAM, no Kubernetes expertise needed) or the standard Helm chart for existing Kubernetes clusters (EKS, GKE, AKS) — typically completes in under one hour. Air-gapped deployment takes longer due to private LLM configuration and image transfer. See the [Getting Started](/) guide for platform-specific setup instructions.

### Does Pixee require code changes to install?

No. Pixee installs as a GitHub App, GitLab integration, Azure DevOps extension, or Bitbucket connector — 4 platforms supported from a single deployment. No code changes, no agents in your CI/CD pipeline, no SDK to add. Pixee reads your scanner results and opens PRs — that is the entire integration surface. You do not need to modify your build system, add dependencies, or change your deployment pipeline. Developers interact with Pixee through standard pull requests in their existing workflow. No new tools to learn, no context-switching required.

### How long does it take to see results from automated remediation?

Most teams see their first automated fix within hours of connecting a scanner with existing findings. Triage results appear even faster -- Pixee begins classifying findings as soon as scanner data is available. Developers interact with Pixee through standard PRs in their existing platform, so there is no adoption curve or behavioral change required from the development team.

### Can Pixee fix vulnerabilities across multiple languages?

Yes. Pixee supports 6 languages: Java, Python, JavaScript/TypeScript, .NET, Go, and PHP. Each language has dedicated codemods for SAST and SCA findings. Java and Python have the deepest codemod libraries, with JavaScript/TypeScript close behind. Coverage varies by language and finding type. See the [Language Support Overview](/languages/overview) for the full coverage matrix.

### What is the difference between Pixee and GitHub Copilot Autofix?

Copilot Autofix is limited to GitHub Advanced Security (CodeQL) findings on GitHub. Pixee works with 12 natively integrated scanners across GitHub, GitLab, Azure DevOps, and Bitbucket -- 4 platforms, not one. Pixee also provides triage automation, which Copilot Autofix does not offer. Both capabilities -- triage and remediation -- work across your full scanner stack, not just one tool on one platform. Pixee uses deterministic codemods alongside constrained AI, while Copilot Autofix relies on general-purpose AI code generation. Pixee also supports self-hosted and air-gapped deployment with Bring Your Own Model (BYOM) -- requirements common in financial services, healthcare, and government environments that Copilot Autofix does not address.

## Platform Capabilities

### What programming languages does Pixee support?

Java, Python, JavaScript/TypeScript, .NET, Go, and PHP -- 6 languages total. Each language has dedicated codemods for SAST and SCA findings. Java and Python have the most comprehensive coverage. See the [Language Support](/languages/overview) pages for per-language details including supported finding types and scanner coverage.

### Does Pixee support SCA (software composition analysis) remediation?

Yes. Pixee handles transitive dependency resolution, breaking change detection, and dependency upgrade testing. SCA fixes are more complex than SAST fixes because changing a dependency can cascade across the dependency tree — a single upgrade can ripple through dozens of transitive dependencies. Pixee's SCA pipeline validates compatibility before proposing upgrades and delivers the result as a standard PR for developer review. Both triage and remediation apply to SCA findings, so vulnerable dependencies are classified for exploitability before fix effort is invested.

### Can I customize which vulnerabilities Pixee fixes?

Yes. PIXEE.yaml configuration lets you control which finding types Pixee addresses, which repositories are active, and what approval workflows apply. You can exclude specific files, directories, or finding categories. You can also disable specific codemods by ID for fine-grained control. This is useful during phased rollouts — many teams start with a subset of repositories and finding types, then expand as confidence builds. See the [PIXEE.yaml Reference](/configuration/pixee-yaml) for configuration syntax and examples.

### What happens when a Pixee PR conflicts with another PR?

Pixee PRs are standard Git pull requests. Merge conflicts are handled the same way as any other PR -- rebase, merge the conflicting PR first, or close the Pixee PR. Pixee regenerates the fix on its next analysis cycle if the finding still exists.

### What happens when two findings affect the same code block?

Pixee generates separate PRs for separate findings. If fixes overlap on the same lines, the second PR may have a merge conflict after the first is merged. Close the conflicting PR and Pixee will regenerate it with the updated code context.
