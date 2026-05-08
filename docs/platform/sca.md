---
title: SCA Capabilities
slug: /platform/sca
track: leader
content_type: conceptual
seo_title: "SCA Triage & Remediation | Dependency Vulnerabilities"
description: How Pixee applies exploitability analysis to dependency vulnerabilities and delivers atomic upgrade PRs with code-level fixes.
sidebar_position: 5
---

Pixee applies the same triage and remediation model to third-party dependency vulnerabilities that it applies to first-party code findings. When your existing SCA tools flag a CVE, Pixee determines whether the vulnerability is actually exploitable in your specific codebase -- not just whether the version is affected. Confirmed vulnerabilities get atomic upgrade PRs that include both the manifest version bump and any downstream source-file changes. The result: 85% SCA noise reduction and 90% less triage time.

SCA capabilities are part of Pixee's unified pipeline. SAST and SCA findings flow through the same triage and [remediation](/platform/remediation) infrastructure -- no separate tools, no context-switching between first-party and third-party vulnerabilities.

## Version Matching vs. Exploitability

Standard SCA tools flag every CVE associated with an affected dependency version, regardless of actual exploitability:

- **Version matching is not vulnerability matching.** A CVE may require specific configuration or API usage that your code never exercises.
- **CVSS scores carry zero codebase context.** A CVSS 9.8 in a library where the vulnerable function is never called does not represent a 9.8 in the application.

## Exploitability Verification for Dependencies

Pixee answers "Can this CVE actually be triggered in this codebase?" -- not just "Is this version theoretically affected?"

**How exploitability verification works:**

| Step                                 | What Happens                                                                                                                                                                                               |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1. External research**             | A CVE research agent gathers CVE details, changelogs, patches, and release notes to identify the specific conditions required for exploitation                                                             |
| **2. Internal analysis**             | The triage agent examines how the library is actually used in your code -- which functions are called, what input reaches them, what security controls exist                                               |
| **3. Evidence-based classification** | Every "Not Exploitable" includes the conditions the CVE requires, analysis of each condition against your code, code snippets demonstrating why conditions are or are not met, and a defensible conclusion |
| **4. Cache acceleration**            | Verified CVE+dependency combinations are cached. The same analysis is not repeated across repositories sharing common dependencies                                                                         |

**Concrete example:** A scanner flags a Spring WebFlux static resource authorization bypass (CVSS 6.9). The CVE requires three conditions: WebFlux controllers, Spring static resource handling, and a non-permitAll security rule. Pixee's analysis finds no WebFlux controllers, no Spring static resource APIs, and no non-permitAll protection rules. Two of three conditions are unmet. Classification: Not Exploitable, with the evidence.

This is the difference between reachability ("does a code path exist?") and exploitability ("can an attacker actually walk it?"). Reachability is necessary but not sufficient. Pixee layers data flow analysis and condition verification on top of call-graph analysis to answer the question that matters.

## Dependency Remediation

When an SCA finding is triaged as a true positive, Pixee handles the fix through the same remediation pipeline as SAST findings:

**Justified upgrades only.** The dependency agent bumps a version only when a verified vulnerability and exploitable path justify the change. No blind version bumping.

**Atomic PRs.** A single Pixee PR contains both the manifest version bump AND the downstream source-file changes the upgrade requires. When a major version upgrade changes an API, the import statements and call sites are updated in the same diff. No "upgrade succeeded, tests broken" half-states.

**Multi-manifest support:**

| Language   | Supported Manifest Formats                                     |
| ---------- | -------------------------------------------------------------- |
| Python     | requirements.txt, pyproject.toml, Pipfile, setup.py, setup.cfg |
| Java       | pom.xml, build.gradle                                          |
| JavaScript | package.json                                                   |
| .NET       | .csproj, packages.config                                       |

**Fix evaluation gate.** The same three-dimension quality rubric (Safety, Effectiveness, Cleanliness) that validates SAST fixes also validates dependency upgrade PRs. The evaluator confirms the upgrade resolves the vulnerability without introducing breaking changes.

**Multi-file coordination.** The fix planning system coordinates across manifest files, source files, and configuration. Complex dependency upgrades that require code changes alongside the version bump are handled as a single, reviewable unit of work.

## Transitive Dependency Handling

Modern applications have hundreds to thousands of transitive dependencies. A vulnerability four layers deep through an unused code path is not the same risk as a direct exposure.

Pixee handles transitive dependencies through full chain analysis:

**Full chain tracing.** Traces the dependency chain from your application root through every intermediate library to the vulnerable package. Not just "library X has CVE Y" but "your app imports A, which imports B, which imports the vulnerable function in C."

**TID identification.** Pixee surfaces the Taint Introducing Dependency -- the direct dependency in your manifest that begins the chain to the vulnerable transitive dependency. This tells developers exactly which dependency to address.

**Severity calibration by depth.** Risk is adjusted based on the depth and nature of the dependency chain. A vulnerability in a direct dependency with proven reachability is higher risk than the same CVE four layers deep through an unused code path.

**Combined blast radius.** When multiple dependencies lead to the same vulnerable transitive dependency, Pixee surfaces the combined exposure so teams understand the full scope.

## Unified Pipeline

SCA and SAST findings flow through the same triage engine, remediation pipeline, and PR delivery. SAST results inform SCA risk scoring -- a SAST finding in code that calls a vulnerable dependency function changes the exploitability calculus. No context-switching between tools, no separate dashboards.

## Frequently Asked Questions

### What is reachability analysis for SCA findings?

Reachability analysis checks whether a vulnerable function in a dependency is reachable from your application code. Pixee goes further with exploitability analysis -- determining whether the specific conditions required to trigger the CVE are actually met in your codebase, not just whether a code path exists. The difference matters: a reachable function protected by a sanitizer is reachable but not exploitable.

### How does Pixee handle transitive dependencies?

Pixee traces the full dependency chain from your application through every intermediate library to the vulnerable package. It identifies exactly which direct dependency in your manifest to upgrade and coordinates manifest changes with downstream source-file refactoring in a single atomic PR.

### Does Pixee replace my existing SCA tool?

No. Pixee sits downstream of your existing SCA tools (Snyk, Trivy, and others). Your scanners continue to detect dependency vulnerabilities. Pixee adds exploitability verification and automated remediation on top. You do not need to change your detection stack.

### What happens when a dependency upgrade would break my code?

Pixee's dependency agent does not blindly upgrade to the latest version. It analyzes changelog data, API changes, and framework compatibility to select the right target version. The fix planning system includes downstream source-file changes in the same PR when an upgrade changes APIs. The fix evaluation gate validates that the upgrade does not introduce breaking changes before the PR is created.
