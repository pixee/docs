---
title: Codemodder Framework
slug: /open-source/codemodder
track: dev
content_type: guide
seo_title: Codemodder Framework -- Pixee Docs
description: Codemodder open source framework for building security-focused code transformations. Supports Java and Python.
sidebar_position: 1
---

# Codemodder Framework

Codemodder is an open source framework created by Pixee for building language-specific, security-focused code transformations called codemods. Each codemod encodes a specific security remediation pattern — SQL injection parameterization, insecure deserialization hardening, cryptography upgrades — as a deterministic, testable rule. Codemodder currently supports Java via [codemodder-java](https://github.com/pixee/codemodder-java) and Python via [codemodder-python](https://github.com/pixee/codemodder-python), with every codemod publicly inspectable on GitHub.

Automated code changes demand trust. Open source engines provide that transparency in a way that proprietary black-box tools cannot — security teams and auditors can inspect the exact transformation rules before trusting automated remediation in their codebase.

All projects are licensed under **Apache 2.0**.

## Projects

| Project                                                          | Language       | Description                                                                     |
| ---------------------------------------------------------------- | -------------- | ------------------------------------------------------------------------------- |
| [codemodder-java](https://github.com/pixee/codemodder-java)      | Java           | Java codemod engine with AST transformations via ParseAndGo                     |
| [codemodder-python](https://github.com/pixee/codemodder-python)  | Python         | Python codemod engine with LibCST, regex, and XML transformers                  |
| [Codemodder framework](https://github.com/pixee/codemodder-spec) | Multi-language | Core specification and framework for building language-specific codemod engines |

## What Codemods Are

A security codemod is a deterministic rule that transforms insecure code into secure code. "Deterministic" means same input produces the same output every time — no LLM, no variance, no hallucination. Codemods encode decades of OWASP and SANS best practices into testable, repeatable rules.

For example, a codemod detects raw SQL string concatenation and transforms it into parameterized queries. The fix is the same whether you run it today or a year from now. That predictability is what makes codemods suitable for automated remediation in production codebases.

## Architecture

Codemodder has three layers:

**Framework layer.** Core abstractions for codemod registration, file discovery, transformation execution, and output generation. This layer defines how codemods are built, configured, and run regardless of target language.

**Language engines.** Language-specific implementations that plug into the framework:

- **codemodder-java** uses ParseAndGo-based AST transformations. Codemods register into a default codemod set and operate on Java abstract syntax trees.
- **codemodder-python** supports three transformer strategies: LibCST for AST-level transformations, regex for pattern-based changes, and XML for configuration files. A single Python codemod can target source files, config files, or dependency manifests.

**Output format.** All engines produce a structured JSON report describing every change made — including what was modified, where, and the security rationale — designed to integrate into CI/CD pipelines or review workflows.

## How Codemods Work

The transformation pipeline follows a consistent flow from scanner finding to structured output:

1. **Scanner produces a finding.** A SAST or SCA tool flags a vulnerability and emits a SARIF report identifying the file, line, and rule that triggered.
2. **Codemodder matches a codemod rule.** The engine checks whether a registered codemod handles the finding type (e.g., CWE-89 for SQL injection maps to the SQL parameterization codemod).
3. **The codemod analyzes the vulnerable code.** Using AST parsing (ParseAndGo for Java, LibCST for Python), regex matching, or XML parsing, the codemod identifies the exact code pattern that needs to change.
4. **The transformation applies the security fix.** The codemod rewrites the code deterministically.
5. **The engine writes a structured report.** A JSON document describes what changed and why — both human-readable and machine-parseable.
6. **Developer reviews the change.** In the Pixee platform, the fix becomes a pull request. With the standalone engine, you review the structured report and the modified files directly.

## codemodder-java

The Java engine provides a library of deterministic codemods using ParseAndGo-based AST transformations.

**Fix categories covered:**

- SQL injection parameterization
- SSRF prevention
- Insecure deserialization hardening
- Weak cryptography replacement (secure random, algorithm upgrades)
- Insecure temp file handling
- SSL/TLS protocol upgrades
- Security hardening patterns from OWASP/SANS

**Running codemodder-java:**

```bash
# Clone and build
git clone https://github.com/pixee/codemodder-java.git
cd codemodder-java
./gradlew build

# Run against a target project
./gradlew run --args="--source /path/to/project --output results.json"

# Run specific codemods only
./gradlew run --args="--source /path/to/project --codemod-include pixee:java/sql-parameterizer --output results.json"
```

## codemodder-python

The Python engine provides a library of deterministic codemods with three distinct transformer strategies.

**Transformer strategies:**

| Strategy | Target                       | Use Case                                                               |
| -------- | ---------------------------- | ---------------------------------------------------------------------- |
| LibCST   | Python source files          | AST-level transformations (function calls, imports, class definitions) |
| Regex    | Config and source files      | Pattern-based replacements where AST parsing is unnecessary            |
| XML      | Dependency manifests, config | XML configuration files and dependency declarations                    |

A single codemod can combine strategies. For example, a PyYAML hardening codemod might use LibCST to change `yaml.load()` calls to `yaml.safe_load()` in source files while also updating a requirements file via regex.

**Fix categories covered:**

- SQL injection parameterization
- SSRF prevention
- PyYAML safe loading
- Defused XML parsing
- Weak cryptography replacement (secure random, JWT decode verification)
- Security hardening patterns from OWASP/SANS

**Running codemodder-python:**

```bash
# Install
pip install codemodder

# Run against a target project
codemodder /path/to/project --output results.json

# Run specific codemods only
codemodder /path/to/project --codemod-include pixee:python/secure-random --output results.json

# Exclude directories
codemodder /path/to/project --path-exclude tests/ vendor/ --output results.json
```

## Open Source vs. Pixee Platform

The open source engines and the commercial Pixee platform serve different needs.

**Open source engines** provide deterministic codemods only. No AI, no triage, no scanner integration, no PR workflow. You run them locally or in CI/CD and get structured output describing every change.

**The Pixee platform** builds on the open source engines and adds:

- **AI-powered fixes** for vulnerability patterns that deterministic rules cannot reach (custom frameworks, multi-file dataflows, context-dependent sanitization)
- **Triage Automation** with false positive reduction via exploitability analysis
- **Native scanner integrations** — see [Integrations](/integrations/overview) for the full list
- **Pull request delivery** so developers review fixes through their existing code review process
- **Enterprise deployment** options including embedded cluster, Helm, and air-gapped environments

The open source layer is the deterministic foundation. The platform adds intelligence, automation, and enterprise workflow on top.

## Custom Codemods

You can build custom codemods on the Codemodder framework for your organization's internal security patterns — internal framework wrappers, custom query builders, organization-specific coding standards. See the [Custom Codemods](/open-source/custom-codemods) tutorial for step-by-step instructions.

## Contributing

Contributions are welcome across all Codemodder repositories. New codemods have the highest impact — each one expands the number of vulnerability patterns the community can fix automatically.

**How to contribute:**

1. Browse [`good first issue`](https://github.com/pixee/codemodder-java/labels/good%20first%20issue) tags in [codemodder-java](https://github.com/pixee/codemodder-java/issues) or [codemodder-python](https://github.com/pixee/codemodder-python/issues)
2. Open an issue describing your proposed codemod before writing code — this ensures alignment on approach
3. Fork, branch (`feat/codemod-name`), implement, and add before/after test fixtures
4. Run the full test suite (`./gradlew test` for Java, `pytest` for Python) and verify output against a sample repository
5. Submit a pull request referencing the issue, with sample before/after code

**Quality standards:** Before/after test fixtures are required for every codemod. Codemods must be deterministic — no external API calls, no network dependencies, no randomness. One codemod per PR.

All contributions are submitted under Apache 2.0. Contributors are credited in release notes. See the CONTRIBUTING.md in each repository for the full workflow.
