---
title: Contributing to Pixee Open Source
slug: /open-source/contributing
track: dev
content_type: guide
seo_title: Contributing -- Pixee Docs
description: Contribution guide for codemodder-java, codemodder-python, and related Pixee open source projects.
sidebar_position: 4
---

# Contributing to Pixee Open Source

Pixee's core remediation engine is built on open source. You can contribute codemods (deterministic security fix rules), report bugs, improve documentation, or propose new detection patterns. Contributions go to the Codemodder repositories -- [codemodder-java](https://github.com/pixee/codemodder-java) and [codemodder-python](https://github.com/pixee/codemodder-python) -- under Apache 2.0 license. This guide covers the contribution workflow, quality standards, and community guidelines.

## What You Can Contribute

| Contribution Type | Repositories                       | Impact                                                        |
| ----------------- | ---------------------------------- | ------------------------------------------------------------- |
| **New codemods**  | codemodder-java, codemodder-python | Expands automated fix coverage for a vulnerability pattern    |
| **Bug fixes**     | Any Pixee open source repo         | Fixes issues in existing codemods or framework code           |
| **Documentation** | Any Pixee open source repo         | Improves README, API docs, or usage examples                  |
| **Test cases**    | codemodder-java, codemodder-python | Adds edge case coverage to existing codemods                  |
| **Issue reports** | Any Pixee open source repo         | Identifies bugs, suggests improvements, requests new codemods |

New codemod contributions have the highest impact. Each new codemod directly expands the number of vulnerability patterns that Codemodder can fix automatically. If you want to build a full codemod, start with the [Custom Codemods](/open-source/custom-codemods) tutorial.

## Contribution Workflow

### Step 1: Find or Create an Issue

Browse open issues in [codemodder-java](https://github.com/pixee/codemodder-java/issues) or [codemodder-python](https://github.com/pixee/codemodder-python/issues). Issues tagged **`good first issue`** are specifically scoped for new contributors. Issues tagged **`help wanted`** are ready for community pickup.

If you want to contribute a new codemod, open an issue first describing the vulnerability pattern and your proposed fix. Discuss the approach before writing code. This saves time and ensures your contribution aligns with the project direction.

### Step 2: Fork and Branch

Fork the repository to your GitHub account and create a feature branch from `main`:

```bash
git clone https://github.com/YOUR-USERNAME/codemodder-java.git
cd codemodder-java
git checkout -b feat/my-new-codemod
```

Follow the branch naming convention:

- `feat/codemod-name` for new codemods
- `fix/issue-number` for bug fixes
- `docs/description` for documentation improvements

### Step 3: Implement

For new codemods, follow the [Codemodder](/open-source/codemodder) framework patterns. The [Custom Codemods](/open-source/custom-codemods) page has step-by-step build instructions for both Java and Python.

For bug fixes, include a test that reproduces the bug before your fix and passes after it.

For documentation, follow the existing style and structure in the repository.

### Step 4: Test

Add before/after test fixtures for new codemods and run the full test suite locally:

```bash
# Java
./gradlew test

# Python
pytest
```

Verify that your changes produce a correct structured report by running the codemod against a sample repository.

### Step 5: Submit a Pull Request

Push your branch and open a pull request against `main`:

- Reference the issue number in the PR description
- Describe what the change does and why
- Include sample before/after code if submitting a new codemod
- Ensure CI checks pass

### Step 6: Review and Merge

Pixee maintainers review contributions for code quality, security correctness, and test coverage. Address review feedback promptly. Once approved, maintainers merge the PR.

Security-sensitive contributions receive additional review from the Pixee security team. This is normal and ensures the fix rules meet the same quality bar as all existing codemods.

## Quality Standards

Every contribution must meet these standards:

- **Before/after test fixtures are required** for every codemod. No exceptions.
- **Test coverage must include:** the primary vulnerable pattern, at least one code style variation, and at least one edge case.
- **Codemods must be deterministic.** Same input produces the same output every time. No external API calls, no network dependencies, no randomness in codemod execution.
- **Follow existing code style.** CI linters enforce formatting and conventions automatically.
- **One codemod or fix per PR.** Keep pull requests focused. Multiple unrelated changes in a single PR slow down review.

## Community Guidelines

**Code of Conduct.** All contributors are expected to engage respectfully and constructively. Review the CODE_OF_CONDUCT.md in each repository.

**Issue etiquette.** Search existing issues before opening a new one. When reporting bugs, provide reproduction steps, the codemod involved, and the engine's output report if applicable.

**PR etiquette.** Keep PRs focused. Respond to review feedback. If a maintainer requests changes, address them or explain your reasoning -- both are fine.

**Communication channels:**

- **GitHub Issues** for bugs, feature requests, and codemod proposals
- **GitHub Discussions** for questions, ideas, and general conversation

**License.** All contributions are submitted under Apache 2.0, the same license as the project.

## Recognition

Contributors are credited in release notes when their changes ship. Significant contributors are listed in the project's CONTRIBUTORS file. Particularly impactful codemod contributions may be highlighted in Pixee community updates.

## Where to Start

If this is your first contribution to Pixee:

1. **Browse [`good first issue`](https://github.com/pixee/codemodder-java/labels/good%20first%20issue) tags** in either repository
2. **Read the [Codemodder](/open-source/codemodder) page** to understand the framework architecture
3. **Walk through the [Custom Codemods](/open-source/custom-codemods) tutorial** to see how codemods are built and tested
4. **Pick an issue, discuss it, and submit a PR** -- the maintainers are here to help

Every codemod contributed expands the number of vulnerabilities the community can fix automatically. Your contribution matters.

---

## Frequently Asked Questions

### How do I contribute to Pixee's open source projects?

Fork the repository, create a feature branch, implement your change with tests, and submit a pull request. Browse issues tagged `good first issue` for beginner-friendly contributions. New codemod contributions have the highest impact on the project.

### What license are Pixee's open source projects under?

Pixee's open source projects (codemodder-java, codemodder-python) are licensed under Apache 2.0. All contributions must be submitted under the same license.

### What makes a good first contribution?

Issues tagged `good first issue` are specifically scoped for new contributors with clear requirements. Bug fixes with reproduction steps and documentation improvements are also good starting points. Building a new codemod requires more familiarity with the Codemodder framework, so review the [Custom Codemods](/open-source/custom-codemods) tutorial first.

### Where do I ask questions about contributing?

Use GitHub Discussions in the relevant repository for questions, ideas, and conversation. Use GitHub Issues for specific bugs, feature requests, or codemod proposals. Maintainers are active in both channels.
