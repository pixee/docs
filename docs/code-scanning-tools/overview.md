---
sidebar_position: 4
---

# Code Scanning Tool Fixes

Pixee automatically triages and fixes issues detected by code scanning tools when synced with the results of those scans. This page explains how to integrate code scanning tools with Pixee, so that Pixee may triage and fix the issues those tools find.

# Supported Languages

Pixee can fix issues in Java and Python repositories "out of the box" without a code scanner integration. But, you'll get the most value out of Pixee by connecting it to your existing code scanning tools and services. This will allow Pixee to provide more accurate and relevant fixes for your codebase and to triage findings from those tools.

When triaging and fixing issues detected by code scanning tools, Pixee supports the following languages:

- Java
- Python
- C#/.NET
- JavaScript
- TypeScript
- Node.js

We are continuously working on expanding our language support. If you need support for a language not listed here, please [contact us](https://pixee.ai/demo-landing-page).

# Supported Tools

- [Sonar, SonarCloud, SonarQube](/code-scanning-tools/sonar)
- [Semgrep](/code-scanning-tools/semgrep)
- [CodeQL](/code-scanning-tools/codeql)
- Snyk
- Contrast Security
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
- ... and many more

In addition, Pixee can triage and fix a variety of language-specific code issues.

For detailed information about supported rules, or to request additional rule coverage, please [contact us](https://pixee.ai/demo-landing-page).

# GitHub Action

Pixee provides a [GitHub Action](https://github.com/marketplace/actions/upload-tool-results-to-pixeebot) that can be used to upload the results of code scanning tools to Pixee.

We are also working to support "native" integrations with code scanning tools. If you need support for a tool not listed here, please [contact us](https://pixee.ai/demo-landing-page).
