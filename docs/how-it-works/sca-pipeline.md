---
title: SCA Pipeline
slug: /how-it-works/sca-pipeline
track: both
content_type: guide
seo_title: "How the SCA Pipeline Works | Dependency Vulnerability Fix"
description: How Pixee verifies CVE exploitability in your codebase and delivers atomic dependency upgrade PRs with code-level fixes.
sidebar_position: 4
---

Pixee's SCA pipeline determines whether flagged CVEs are actually exploitable in your specific codebase, then delivers atomic dependency upgrade PRs that include both manifest version bumps and downstream source-file refactoring. The pipeline combines external CVE research with internal code analysis to produce evidence-based classifications -- not just version matching. Confirmed vulnerabilities get coordinated fixes across Python, Java, JavaScript, and .NET manifests, with fix evaluation before any PR is created.

SCA findings flow through the same co-equal triage and remediation pipeline that handles SAST findings. Pixee applies the same exploitability analysis and fix generation methodology to third-party dependency vulnerabilities that it applies to first-party code findings.

## How the SCA Pipeline Works End to End

1. **SCA scanner** (Snyk, Trivy, or any SARIF-producing tool) flags a CVE in a dependency
2. **CVE research** -- gathers CVE details, changelogs, patches, and release notes to identify the specific conditions required for exploitation
3. **Verification cache lookup** -- checks whether this CVE+dependency combination has already been verified, avoiding redundant analysis
4. **Triage synthesis** -- combines external CVE research with internal code analysis, secure coding guidelines, historical triage decisions, and cross-tool context
5. **Classification output** -- Exploitable or Not Exploitable, with evidence, context-adjusted severity, and a transparent verification report
6. **Dependency remediation** (if exploitable) -- identifies the target version, locates the manifest file, coordinates source-file refactoring, and evaluates the fix
7. **Atomic PR** -- manifest bump plus source-file changes in a single reviewable diff

## CVE Exploitability Verification

Pixee determines whether a flagged CVE can actually be triggered in your code, rather than only checking whether a vulnerable version is present.

**How it works:**

**External research.** The system gathers CVE details, changelogs, patches, and release notes to identify the specific exploitation conditions -- for example, "requires WebFlux, Spring static resource handling, and a non-permitAll security rule."

**Internal analysis.** The system examines how the library is actually used in your code: which APIs are called, which configurations are active, and whether attacker-controlled input can reach the vulnerable function.

**Evidence-based classification.** Each verdict includes:

- The specific conditions the CVE requires
- Analysis of each condition against your code
- Code snippets demonstrating why conditions are or are not met
- A defensible conclusion (e.g., "2 of 3 conditions are not met")

The following table summarizes the three approaches to SCA analysis:

| Approach                                | What It Tells You                                                                                     | What It Misses                                                                                                                     |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| **Version matching** (legacy SCA)       | "This dependency version has a known CVE"                                                             | Whether anyone calls the vulnerable function, whether exploitation conditions are met, whether security controls mitigate the risk |
| **Basic reachability**                  | "The vulnerable function is reachable from your code"                                                 | Exploitation preconditions, input validation, configuration states                                                                 |
| **Exploitability verification** (Pixee) | "This CVE requires conditions X, Y, Z. Your code meets/does not meet each one. Here is the evidence." | --                                                                                                                                 |

## Verification Cache

Verified CVE+dependency combinations are cached for reuse across repositories. Organizations with many repositories sharing common dependencies verify once, not N times.

- Significant cost reduction for repeated CVE analysis -- the same library-CVE pair analyzed once accelerates every subsequent encounter
- Cache remains valid until CVE data or dependency context changes
- Particularly valuable for large enterprises where dozens of repositories import the same libraries

## Transitive Dependency Handling

Transitive dependencies require chain analysis. A vulnerability four layers deep through an unused code path carries different risk than a direct exposure.

Pixee traces the full dependency chain from the application root through every intermediate library to the vulnerable package:

- **TID (Taint Introducing Dependency):** The direct dependency in your manifest that begins the chain to the vulnerable transitive dependency. This tells developers exactly which dependency to upgrade.
- **TCD (Taint Consuming Dependency):** The package that actually contains the vulnerable code.
- **Severity calibration by depth and usage:** Risk is adjusted based on the depth and nature of the dependency chain. A vulnerability in a direct dependency with proven reachability is higher risk than the same CVE four layers deep through an unused code path.
- **Blast radius analysis:** When multiple taint-initiating dependencies lead to the same vulnerable transitive dependency, Pixee surfaces the combined blast radius.

This matters because developers need to know which direct dependency to upgrade in their manifest to resolve a transitive vulnerability. Pixee provides that answer directly.

## Dependency Remediation

When an SCA finding is confirmed as exploitable, Pixee generates a justified upgrade -- not a blind version bump.

**Multi-manifest support:**

| Language       | Supported Manifests                                            |
| -------------- | -------------------------------------------------------------- |
| **Python**     | requirements.txt, pyproject.toml, Pipfile, setup.py, setup.cfg |
| **Java**       | pom.xml, build.gradle                                          |
| **JavaScript** | package.json                                                   |
| **.NET**       | .csproj, packages.config                                       |

**How the fix pipeline works for SCA:**

- **Justified upgrades only.** The system only bumps a version when a verified vulnerability and exploitable path justify the change. No blind version bumping.
- **Version selection with compatibility analysis.** Not "upgrade to latest." The system uses framework compatibility, runtime constraints, and historical upgrade patterns to select the right version.
- **Atomic PRs.** A single PR contains the manifest bump AND downstream source-file changes the upgrade requires. No "upgrade succeeded, tests broken" half-states.
- **Fix evaluation.** The same three-dimension rubric (Safety, Effectiveness, Cleanliness) that validates SAST fixes also validates dependency upgrades before PR creation.

## Cross-Tool Intelligence

The SCA pipeline benefits from Pixee's unified platform architecture. SAST and SCA findings share context and inform each other:

| Intelligence Source             | What It Provides                                                                                                  |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| **SAST results**                | Inform SCA risk scoring -- a dependency vulnerability in code that also has SAST findings carries compounded risk |
| **Historical triage decisions** | Prevent re-triaging the same CVEs across repositories                                                             |
| **Secure coding guidelines**    | Team preferences in natural language enrich SCA analysis                                                          |
| **GitHub PRs and Jira tickets** | Previous SCA upgrade context provides upgrade history                                                             |

Because SAST and SCA findings share context in the same pipeline, cross-tool signals are available during analysis.

## Frequently Asked Questions

### What is reachability analysis for SCA findings?

Basic reachability checks whether a vulnerable function in a dependency is reachable from your code. Pixee goes further with exploitability analysis -- determining whether the specific conditions required to trigger the CVE are actually met in your codebase, including data flow analysis and exploitation precondition verification. Each classification includes transparent evidence showing which conditions are met and which are not.

### How does Pixee handle transitive dependencies?

Pixee traces the full dependency chain from your application through every intermediate library to the vulnerable package. It identifies exactly which direct dependency in your manifest to upgrade (TID -- Taint Introducing Dependency) and coordinates the manifest change with downstream source-file refactoring in a single atomic PR. Severity is calibrated based on dependency depth and actual usage patterns.

### Does Pixee just bump dependency versions?

No. Pixee only upgrades when a verified vulnerability justifies the change. Each upgrade PR includes both the manifest version bump and any downstream source-file changes the upgrade requires. Fix evaluation validates the complete change before creating the PR. Version selection considers framework compatibility and historical upgrade patterns, not just "latest available."
