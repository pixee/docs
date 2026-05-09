---
title: SCA
slug: /platform/sca
track: both
content_type: guide
seo_title: "SCA Triage & Remediation | Dependency Vulnerability Verification"
description: How Pixee verifies CVE exploitability in your codebase and delivers atomic dependency upgrade PRs with code-level fixes.
sidebar_position: 5
---

Pixee applies the same triage and remediation model to third-party dependency vulnerabilities that it applies to first-party code findings. When your SCA tools flag a CVE, Pixee determines whether the vulnerability is actually exploitable in your specific codebase — not just whether the version is affected. Confirmed vulnerabilities get atomic upgrade PRs that include both the manifest version bump and any downstream source-file changes.

SCA findings flow through the same triage engine, remediation pipeline, and PR delivery as SAST findings. No separate tools, no context-switching between first-party and third-party vulnerabilities.

## Version Matching vs. Exploitability

Standard SCA tools flag every CVE associated with an affected dependency version, regardless of actual exploitability:

- **Version matching is not vulnerability matching.** A CVE may require specific configuration or API usage that your code never exercises.
- **CVSS scores carry zero codebase context.** A CVSS 9.8 in a library where the vulnerable function is never called does not represent a 9.8 in your application.

Pixee answers "Can this CVE actually be triggered in this codebase?" — not just "Is this version theoretically affected?"

## CVE Exploitability Verification

**How it works:**

| Step                                 | What Happens                                                                                                                                                                                                       |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **1. External research**             | A CVE research agent gathers CVE details, changelogs, patches, and release notes to identify the specific conditions required for exploitation                                                                     |
| **2. Internal analysis**             | The triage agent examines how the library is actually used in your code — which functions are called, what input reaches them, what security controls exist                                                        |
| **3. Evidence-based classification** | Every "Not Exploitable" verdict includes the conditions the CVE requires, analysis of each condition against your code, code snippets demonstrating why conditions are or are not met, and a defensible conclusion |
| **4. Efficient reanalysis**          | Previously evaluated CVE+dependency combinations are not reanalyzed unnecessarily, keeping SCA processing efficient across repositories sharing common dependencies                                                |

**Concrete example:** A scanner flags a Spring WebFlux static resource authorization bypass (CVSS 6.9). The CVE requires three conditions: WebFlux controllers, Spring static resource handling, and a non-permitAll security rule. Pixee's analysis finds no WebFlux controllers, no Spring static resource APIs, and no non-permitAll protection rules. Two of three conditions are unmet. Classification: Not Exploitable, with the evidence.

**The three approaches compared:**

| Approach                                | What It Tells You                                                                                     | What It Misses                                                                                                                  |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **Version matching** (legacy SCA)       | "This dependency version has a known CVE"                                                             | Whether the vulnerable function is called, whether exploitation conditions are met, whether security controls mitigate the risk |
| **Basic reachability**                  | "The vulnerable function is reachable from your code"                                                 | Exploitation preconditions, input validation, configuration states                                                              |
| **Exploitability verification** (Pixee) | "This CVE requires conditions X, Y, Z. Your code meets/does not meet each one. Here is the evidence." | —                                                                                                                               |

## Efficient Reanalysis

Pixee avoids redundant reanalysis of previously evaluated dependency/vulnerability combinations, keeping SCA processing efficient at scale. Organizations with many repositories sharing common dependencies benefit automatically — repeated CVE analysis across repositories is avoided without requiring manual coordination.

## Transitive Dependency Handling

Transitive dependencies require full chain analysis. A vulnerability four layers deep through an unused code path carries different risk than a direct exposure.

**Key concepts:**

- **TID (Taint Introducing Dependency):** The direct dependency in your manifest that begins the chain to the vulnerable transitive dependency. This tells developers exactly which dependency to upgrade.
- **TCD (Taint Consuming Dependency):** The package that actually contains the vulnerable code.
- **Severity calibration by depth:** Risk is adjusted based on the depth and nature of the dependency chain.
- **Blast radius analysis:** When multiple taint-initiating dependencies lead to the same vulnerable transitive dependency, Pixee surfaces the combined exposure.

Pixee traces the full dependency chain from your application root through every intermediate library to the vulnerable package. Developers get a direct answer: which dependency in your manifest to upgrade.

## Dependency Remediation

When an SCA finding is confirmed as exploitable, Pixee generates a justified upgrade — not a blind version bump.

**Justified upgrades only.** The dependency agent bumps a version only when a verified vulnerability and exploitable path justify the change.

**Multi-manifest support:**

| Language       | Supported Manifest Formats                                     |
| -------------- | -------------------------------------------------------------- |
| **Python**     | requirements.txt, pyproject.toml, Pipfile, setup.py, setup.cfg |
| **Java**       | pom.xml, build.gradle                                          |
| **JavaScript** | package.json                                                   |
| **.NET**       | .csproj, packages.config                                       |

**Atomic PRs.** A single Pixee PR contains both the manifest version bump AND the downstream source-file changes the upgrade requires. When a major version upgrade changes an API, the import statements and call sites are updated in the same diff. No "upgrade succeeded, tests broken" half-states.

**Fix evaluation gate.** The same three-dimension quality rubric (Safety, Effectiveness, Cleanliness) that validates SAST fixes also validates dependency upgrade PRs.

## Cross-Tool Intelligence

The SCA pipeline benefits from Pixee's unified platform architecture. SAST and SCA findings share context and inform each other:

| Intelligence Source             | What It Provides                                                                                                 |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| **SAST results**                | Inform SCA risk scoring — a dependency vulnerability in code that also has SAST findings carries compounded risk |
| **Historical triage decisions** | Prevent re-triaging the same CVEs across repositories                                                            |
| **Secure coding guidelines**    | Team preferences in natural language enrich SCA analysis                                                         |
| **GitHub PRs and Jira tickets** | Previous SCA upgrade context provides upgrade history                                                            |
