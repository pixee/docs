---
title: Codemodder Framework
slug: /open-source/codemodder
track: dev
content_type: guide
seo_title: Codemodder Framework -- Pixee Docs
description: Codemodder open source framework for building security-focused code transformations. Supports Java and Python.
sidebar_position: 2
---

# Codemodder Framework

Codemodder is an open source framework created by Pixee for building language-specific, security-focused code transformations called codemods. Each codemod encodes a specific security remediation pattern -- SQL injection parameterization, insecure deserialization hardening, cryptography upgrades -- as a deterministic, testable rule. Codemodder currently supports Java via [codemodder-java](https://github.com/pixee/codemodder-java) (51+ codemods) and Python via [codemodder-python](https://github.com/pixee/codemodder-python) (60+ codemods), with every codemod publicly inspectable on GitHub.

## What Codemods Are

A security codemod is a deterministic rule that transforms insecure code into secure code. "Deterministic" means same input produces the same output every time. No LLM, no variance, no hallucination. Codemods encode decades of OWASP and SANS best practices into testable, repeatable rules.

For example, a codemod might detect raw SQL string concatenation and transform it into parameterized queries. The fix is the same whether you run it today, tomorrow, or a year from now. That predictability is what makes codemods suitable for automated remediation in production codebases.

## Architecture

Codemodder has three layers:

**Framework layer.** Core abstractions for codemod registration, file discovery, transformation execution, and output generation. This layer defines how codemods are built, configured, and run regardless of target language.

**Language engines.** Language-specific implementations that plug into the framework:

- **codemodder-java** uses ParseAndGo-based AST transformations. Codemods register into a default codemod set and operate on Java abstract syntax trees.
- **codemodder-python** supports three transformer strategies: LibCST for AST-level transformations, regex for pattern-based changes, and XML for configuration files. A single Python codemod can target source files, config files, or dependency manifests.

**Output format.** All engines produce CodeTF (Code Transformation Format) output -- a structured JSON description of every change made, including what was modified, where, and the security rationale. CodeTF is machine-readable, making it straightforward to integrate codemod results into CI/CD pipelines or review workflows.

## How Codemods Work

The transformation pipeline follows a consistent flow from scanner finding to structured output:

1. **Scanner produces a finding.** A SAST or SCA tool flags a vulnerability and emits a SARIF report identifying the file, line, and rule that triggered.

2. **Codemodder matches a codemod rule.** The engine checks whether a registered codemod handles the finding type (e.g., CWE-89 for SQL injection maps to the SQL parameterization codemod).

3. **The codemod analyzes the vulnerable code.** Using AST parsing (ParseAndGo for Java, LibCST for Python), regex matching, or XML parsing, the codemod identifies the exact code pattern that needs to change.

4. **The transformation applies the security fix.** The codemod rewrites the code deterministically. For SQL injection, this means converting string concatenation to parameterized queries. For insecure deserialization, it means adding type validation or switching to a safe loader.

5. **CodeTF output describes the result.** The engine writes a structured report of what changed and why. This output is both human-readable and machine-parseable.

6. **Developer reviews the change.** In the Pixee platform, the fix becomes a pull request. With the standalone engine, you review the CodeTF output and the modified files directly.

## codemodder-java

The Java engine provides 51+ core codemods using ParseAndGo-based AST transformations.

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

The Python engine provides 60+ core codemods with three distinct transformer strategies.

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

## Relationship to the Pixee Platform

Codemodder powers the deterministic remediation layer of the Pixee platform. The platform extends Codemodder with:

- **MagicMods** -- AI-powered fixes for patterns that deterministic rules cannot reach (custom framework wrappers, multi-file dataflows, context-dependent sanitization)
- **Triage Automation** -- false positive reduction before fixes are generated
- **Scanner integration** -- 12 native scanner integrations plus universal SARIF support
- **PR workflow** -- fixes delivered as pull requests through GitHub, GitLab, Azure DevOps, or Bitbucket

Codemodder handles the known, well-understood vulnerability patterns. MagicMods extend coverage to the long tail. Both produce fixes that pass through the same quality evaluation before reaching a developer.

## Next Steps

- **Build your own codemod:** The [Custom Codemods](/open-source/custom-codemods) tutorial walks through building a codemod from scratch
- **Contribute to the project:** See the [Contributing](/open-source/contributing) guide for community participation
- **Explore the full platform:** The Pixee platform adds AI-powered remediation and triage on top of Codemodder -- [learn how fix generation works](/how-it-works/fix-generation)

---

## Frequently Asked Questions

### What is Codemodder?

Codemodder is an open source framework created by Pixee for building deterministic, security-focused code transformations. It supports Java (51+ codemods) and Python (60+ codemods), with a combined 110+ codemods publicly available on GitHub.

### What is a codemod in security?

A security codemod is a deterministic rule that transforms insecure code into secure code. Unlike AI-generated fixes, codemods produce the same output for the same input every time. There is no LLM involved, no variance, and no hallucination risk. Each codemod encodes a specific OWASP or SANS remediation pattern.

### Can I run Codemodder without the Pixee platform?

Yes. Codemodder is a standalone open source tool. Run it locally or in CI/CD to apply deterministic security fixes. The Pixee platform adds AI-powered MagicMods, triage automation, scanner integration, and enterprise deployment on top of Codemodder.

### How does Codemodder relate to the Pixee platform?

Codemodder powers the deterministic remediation layer. The Pixee platform builds on Codemodder and adds AI-powered fixes for novel patterns, triage automation for false positive reduction, native scanner integrations, and pull request delivery through your existing code review workflow.

### What languages does Codemodder support?

Codemodder currently supports Java (codemodder-java, 51+ codemods using ParseAndGo AST transformations) and Python (codemodder-python, 60+ codemods using LibCST, regex, and XML transformers).
