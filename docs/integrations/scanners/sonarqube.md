---
title: SonarQube Integration
slug: /integrations/scanners/sonarqube
track: both
content_type: guide
seo_title: SonarQube Integration with Pixee
description: Pixee integration with SonarQube and SonarCloud for automated triage and remediation, including security hotspot classification.
sidebar_position: 13
---

# SonarQube Integration

Pixee integrates natively with SonarQube and SonarCloud to triage findings and deliver remediation as pull requests. SonarQube's security hotspots require manual review -- Pixee automates that review with code-level justification and generates fixes for confirmed vulnerabilities.

## What SonarQube Detects

SonarQube (self-hosted) and SonarCloud (SaaS) are the most widely deployed code quality and security analysis platforms in the industry. Often the first analysis tool adopted by engineering teams, SonarQube combines SAST with code quality, technical debt, and coverage analysis across 30+ languages.

SonarQube detects:

- **Static Application Security Testing (SAST)** -- OWASP Top 10, CWE coverage, injection flaws, cross-site scripting, authentication issues
- **Security hotspots** -- code patterns that require manual security review before being classified as safe or vulnerable
- **Code quality issues** -- bugs, code smells, and technical debt
- **Code coverage analysis** -- test coverage tracking
- **Duplication detection** -- identifying copy-paste patterns across the codebase

## How Pixee Enhances SonarQube

### Triage

SonarQube's security hotspot system explicitly requires manual review -- a developer or security engineer must investigate each hotspot and classify it as safe or vulnerable. For teams with hundreds or thousands of hotspots, this manual process creates a permanent backlog.

Pixee automates that review. Each SonarQube finding -- including security hotspots -- is processed through Pixee's triage pipeline, which classifies it as TRUE_POSITIVE, FALSE_POSITIVE, or WONT_FIX with a code-level justification. The triage engine investigates the actual codebase to determine whether a hotspot represents a genuine risk.

For teams managing SonarQube's high-volume output, where security findings mix with code quality findings and hotspots in a single dashboard, Pixee separates what matters from what does not.

### Remediation

SonarQube shows what is wrong but does not generate fixes. Pixee fills this gap by delivering remediation as pull requests. True positive findings from SonarQube are automatically fixed using deterministic codemods and AI-powered MagicMods for complex scenarios. Dedicated prompt builders in the remediation engine handle SonarQube-specific finding formats.

Fixes match your team's code conventions.

For the full list of vulnerability types Pixee triages and fixes, see [What Pixee Fixes](/platform/what-pixee-fixes).

## Supported Languages

Pixee remediates SonarQube findings for these languages:

| Language              | Deterministic Codemods | AI-Powered Fixes | SonarQube Rules Covered                        |
| --------------------- | ---------------------- | ---------------- | ---------------------------------------------- |
| Java                  | Yes (51+)              | Yes              | Injection, XSS, crypto, auth, hotspots         |
| Python                | Yes (60+)              | Yes              | Injection, XSS, hardcoded secrets, hotspots    |
| JavaScript/TypeScript | Expanding              | Yes              | XSS, injection, auth patterns                  |
| .NET                  | Expanding              | Yes              | Injection, crypto, configuration               |
| PHP                   | Expanding              | Yes              | Injection, XSS                                 |
| Go                    | —                      | —                | Not currently supported for SonarQube findings |

If your primary SonarQube backlog is in Go, Pixee cannot remediate those findings today. Go support for SonarQube findings is on the roadmap.

## Setup

### Prerequisites

- SonarQube 9.x or later (self-hosted) or SonarCloud (SaaS) with existing scan results
- A Pixee account with at least one repository connected ([Getting Started](/))
- A SonarQube user token with **Browse** and **Administer** project permissions (not a global analysis token)

Connect SonarQube by providing your instance URL and a user token with Browse and Administer project permissions. Pixee queries SonarQube directly via API -- no SARIF export needed. SonarQube projects are mapped to code repositories using the project key; if your project keys match your repository names, mapping is automatic. For enterprise self-hosted deployments, configure SonarQube credentials in your Helm values. For step-by-step configuration, see the [installation guide](https://app.pixee.ai/docs/setup).

### What Happens with Large Backlogs

If your SonarQube instance has thousands of findings, Pixee does not open thousands of PRs simultaneously. Findings are prioritized by severity (Critical and High first), and PR creation is controlled by your configured batch settings. See [Operations](/configuration/operations) for PR volume controls.

## SonarQube Finding Examples

### Example 1: SQL Injection (java:S3649)

**SonarQube finding:** `Change this code to not construct SQL queries directly from user-controlled data.`

**Before (vulnerable):**

```java
String query = "SELECT * FROM users WHERE id = " + request.getParameter("id");
ResultSet rs = statement.executeQuery(query);
```

**Pixee fix (deterministic codemod):**

```java
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement ps = connection.prepareStatement(query);
ps.setString(1, request.getParameter("id"));
ResultSet rs = ps.executeQuery();
```

### Example 2: Hardcoded Credentials (java:S2068)

**SonarQube finding:** `Remove this hard-coded password.`

**Before:** `private static final String DB_PASSWORD = "admin123";`

**Pixee fix (AI-powered):** Moves the credential to an environment variable reference and adds documentation for the required configuration change.

### Example 3: Security Hotspot — CSRF (java:S4502)

**SonarQube hotspot:** `Make sure disabling Spring Security's CSRF protection is safe here.`

**Pixee triage result:** `FALSE_POSITIVE — This endpoint is a REST API consumed by a mobile client using Bearer token authentication. CSRF protection is not applicable to token-authenticated APIs. The Spring Security configuration correctly disables CSRF for the /api/** path only.`

## Common False Positive Patterns Pixee Eliminates

- **Security hotspots that are actually safe:** Pixee's triage engine investigates the actual code context and determines whether the flagged pattern is exploitable -- automating the manual review SonarQube requires
- **Code quality findings conflated with security:** SonarQube mixes code smells, bugs, and security findings in one dashboard; Pixee distinguishes genuine security issues from code quality noise
- **Framework-mitigated injection patterns:** Findings where the application framework provides protection (parameterized queries via ORM, CSRF tokens via framework middleware)
- **Test code at production severity:** SonarQube scans test directories by default; Pixee adjusts classification for non-production code

See [Integrations Overview](/integrations/overview) for the full scanner coverage matrix.
