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

Pixee can triage (T) and/or fix (F) a wide range of security issues detected by code scanning tools. Many of these issues are common across tools and languages, such as:

- SQL Injection (T+F)
- Cross-Site Scripting (XSS) (T+F)
- Insecure Deserialization (T+F)
- Insecure Randomness (T+F)
- XML External Entity (XXE) (F)
- Insecure Cookie Handling (F)
- Command Injection (T+F)
- Insecure Configuration (T)
- Sensitive Data Logging (T)
- Resource Leak (F)
- Detailed Error Messages (T+F)
- SSRF (T+F)
- Hardcoded Passwords (T)
- XPath Injection (T+F)
- HTTP Response Splitting / Response Smuggling / Header Injection (T+F)
- Log Forging (T+F)
- Path Traversal (T)
- Open Redirect (T)
- ... and more!

In addition, Pixee can triage and fix a variety of tool-specific, language-specific and code quality issues, too!

Note that as we add support 

# GitHub Action

Pixee provides a [GitHub Action](https://github.com/marketplace/actions/upload-tool-results-to-pixeebot) that can be used to upload the results of code scanning tools to Pixee.

We are also working to support "native" integrations with code scanning tools. If you need support for a tool not listed here, please [contact us](https://pixee.ai/demo-landing-page).
