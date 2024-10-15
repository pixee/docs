---
sidebar_position: 4
---

# Code Scanner support

Pixee automatically triages and fixes issues detected by code scanning tools when synced with the results of those scans. This page explains how to integrate code scanning tools with Pixee.

# Supported Tools

- [Sonar (SonarCloud and SonarQube)](/code-scanning-tools/sonar)
- [Semgrep](/code-scanning-tools/semgrep)
- [CodeQL](/code-scanning-tools/codeql)
- [Snyk](/code-scanning-tools/snyk)
- [Contrast Security](/code-scanning-tools/contrast)
- HCL AppScan
- Checkmarx (beta)

# Supported Rules

Pixee can triage and fix a wide range of security issues detected by code scanning tools. Many of these issues are common across tools and languages, such as:

- SQL Injection
- Cross-Site Scripting (XSS)
- Insecure Deserialization
- Insecure Randomness
- XML External Entity (XXE)
- Insecure Cookie Handling
- Command Injection
- Insecure Configuration
- Sensitive Data Logging
- Detailed Error Messages
- ... and many more!

In addition, Pixee can triage and fix a variety of language-specific and code quality issues, too!

For detailed information about supported rules, or to request additional rule coverage, please [contact us](https://pixee.ai/demo-landing-page).

# GitHub Action

Pixee provides a [GitHub Action](https://github.com/marketplace/actions/upload-tool-results-to-pixeebot) that can be used to upload the results of code scanning tools to Pixee.

We are also working to support "native" integrations with code scanning tools. If you need support for a tool not listed here, please [contact us](https://pixee.ai/demo-landing-page).
