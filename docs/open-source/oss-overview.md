---
title: Open Source Overview
slug: /open-source/overview
track: dev
content_type: guide
seo_title: Open Source Overview -- Pixee Docs
description: "Pixee open source projects: codemodder-java, codemodder-python, and the Codemodder framework for security-focused code transformations."
sidebar_position: 1
---

# Open Source Overview

Pixee maintains several open source projects that form the foundation of its deterministic remediation engine. The [Codemodder](/open-source/codemodder) framework provides language-specific engines for building security-focused code transformations. [codemodder-java](https://github.com/pixee/codemodder-java) (51+ codemods) and [codemodder-python](https://github.com/pixee/codemodder-python) (60+ codemods) are publicly inspectable on GitHub. These open source engines let customers and auditors review fix rules before trusting automated remediation in their codebase.

## Why Open Source Matters for Security Remediation

Automated code changes demand trust. When a tool modifies your source files, you need to know exactly what it does and why. Open source engines provide that transparency in a way that proprietary black-box tools cannot.

**Trust through transparency.** Every deterministic codemod in Pixee's open source repositories is readable. Security teams and auditors can inspect the exact transformation rules that will be applied to their code. If a codemod parameterizes SQL queries or hardens deserialization, the logic is right there in the repository.

**Community validation.** Open source codemods benefit from review and contribution by security engineers outside Pixee. Bugs get found faster. Edge cases get covered. The fix rules improve over time because more eyes are on the code.

**Extensibility.** Organizations can build [custom codemods](/open-source/custom-codemods) on the Codemodder framework for their own internal security patterns. The framework is designed for extension, not just consumption.

## Pixee Open Source Projects

| Project                                                          | Language       | Codemods | Description                                                                     |
| ---------------------------------------------------------------- | -------------- | -------- | ------------------------------------------------------------------------------- |
| [codemodder-java](https://github.com/pixee/codemodder-java)      | Java           | 51+ core | Java codemod engine with AST transformations via ParseAndGo                     |
| [codemodder-python](https://github.com/pixee/codemodder-python)  | Python         | 60+ core | Python codemod engine with LibCST, regex, and XML transformers                  |
| [Codemodder framework](https://github.com/pixee/codemodder-spec) | Multi-language | N/A      | Core specification and framework for building language-specific codemod engines |

All projects are licensed under Apache 2.0.

## Open Source vs. Pixee Platform

The open source engines and the commercial Pixee platform serve different needs. Understanding the boundary helps you choose the right tool.

**Open source engines** provide deterministic codemods only. No AI, no triage, no scanner integration, no PR workflow. You run them locally or in CI/CD against your codebase and get structured output describing every change.

**The Pixee platform** builds on the open source engines and adds:

- **AI-powered MagicMods** for vulnerability patterns that deterministic rules cannot reach (custom frameworks, multi-file dataflows, context-dependent sanitization)
- **Triage Automation** with false positive reduction via exploitability analysis
- **12 native scanner integrations** that ingest findings from Semgrep, CodeQL, Sonar, Snyk, and others
- **Pull request delivery** so developers review fixes through their existing code review process
- **Enterprise deployment** options including embedded cluster, Helm, and air-gapped environments

The open source layer is the deterministic foundation. The platform adds intelligence, automation, and enterprise workflow on top.

## Getting Started with Open Source

To run the open source codemod engines locally:

**Java:**

```bash
# Clone the repository
git clone https://github.com/pixee/codemodder-java.git

# Build and run against your project
./gradlew run --args="--source /path/to/your/project --output results.json"
```

**Python:**

```bash
# Install from PyPI
pip install codemodder

# Run against your project
codemodder /path/to/your/project --output results.json
```

The engines produce a structured JSON report describing every transformation applied, what changed, and why.

From here:

- Read the [Codemodder](/open-source/codemodder) page for architecture details and the full codemod catalog
- Build your own security rules with the [Custom Codemods](/open-source/custom-codemods) tutorial
- Join the community through our [Contributing](/open-source/contributing) guide

## License

All Pixee open source projects are released under the **Apache License 2.0**. You can use, modify, and distribute the code in both open source and commercial projects. Contributions are accepted under the same license.

---

