---
title: What Pixee Fixes
slug: /platform/what-pixee-fixes
track: both
content_type: reference
seo_title: "What Pixee Fixes | Vulnerability Types, Triage, and Fix Modes"
description: Canonical reference for all vulnerability types, finding categories, and fix modes Pixee handles across SAST, SCA, and IaC findings.
sidebar_position: 3
---

This page is the canonical reference for what Pixee can triage and fix. It covers all vulnerability types and finding categories across SAST, SCA, and IaC findings.

## Vulnerability Coverage Table

| Vulnerability Category                             | Examples                                                                                                              | Triage | Fix Mode             |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------ | -------------------- |
| **Injection — SQL**                                | SQL injection via string concatenation, unparameterized queries                                                       | Yes    | Deterministic / Both |
| **Injection — Command**                            | OS command injection, shell metacharacters in exec calls                                                              | Yes    | Deterministic / Both |
| **Injection — LDAP**                               | LDAP injection via unsanitized directory search filters                                                               | Yes    | AI                   |
| **Injection — XPath**                              | XPath injection via user-controlled node selection                                                                    | Yes    | AI                   |
| **Injection — NoSQL**                              | NoSQL injection in MongoDB, Redis, and similar query patterns                                                         | Yes    | AI                   |
| **Injection — Expression Language**                | EL/OGNL injection via template or framework evaluation                                                                | Yes    | AI                   |
| **Cross-Site Scripting (XSS) — Reflected**         | Reflected XSS via unencoded user input in HTTP responses                                                              | Yes    | Deterministic / Both |
| **Cross-Site Scripting (XSS) — Stored**            | Stored XSS persisted in database and rendered to other users                                                          | Yes    | Both                 |
| **Cross-Site Scripting (XSS) — DOM-Based**         | DOM XSS via document.write, innerHTML, eval with user data                                                            | Yes    | Both                 |
| **Path Traversal**                                 | Directory traversal via `../` sequences, file inclusion flaws                                                         | Yes    | Deterministic / Both |
| **Server-Side Request Forgery (SSRF)**             | SSRF via unvalidated URL parameters to internal or cloud metadata endpoints                                           | Yes    | Deterministic / Both |
| **Insecure Deserialization**                       | Unsafe deserialization of untrusted data                                                                              | Yes    | Both                 |
| **Weak Cryptography**                              | MD5, SHA-1 for security-sensitive operations; ECB mode; short key lengths                                             | Yes    | Deterministic / Both |
| **Insecure Randomness**                            | Insecure random number generators used for security-sensitive tokens                                                  | Yes    | Deterministic / Both |
| **Hardcoded Secrets**                              | Hardcoded API keys, passwords, tokens in source code                                                                  | Yes    | AI                   |
| **Authentication / Session Weaknesses**            | Broken authentication, session fixation, missing session invalidation, insecure cookie flags                          | Yes    | Both                 |
| **Insecure Direct Object Reference (IDOR)**        | Missing authorization checks on resource identifiers                                                                  | Yes    | AI                   |
| **XML / XXE Vulnerabilities**                      | XML External Entity injection, DTD processing, XXE via SSRF                                                           | Yes    | Deterministic / Both |
| **Insecure Temp Files**                            | Predictable temp file creation, race conditions on tempfile usage                                                     | Yes    | Deterministic / Both |
| **Logging Sensitive Data**                         | PII, credentials, tokens written to logs                                                                              | Yes    | AI                   |
| **Security Misconfigurations**                     | Missing security headers, insecure defaults, disabled CSRF protection                                                 | Yes    | Both                 |
| **SSL/TLS Weaknesses**                             | Disabled hostname verification, accepting all certificates, weak protocols                                            | Yes    | Deterministic / Both |
| **Dependency Vulnerabilities (SCA)**               | CVEs in direct and transitive open-source dependencies                                                                | Yes    | Deterministic / Both |
| **Container / Dockerfile Misconfigurations**       | Running as root, insecure base image patterns, exposed secrets in layers                                              | Yes    | Both                 |
| **Infrastructure as Code (IaC) Misconfigurations** | Terraform / CloudFormation / Kubernetes / Helm security misconfigurations, overly permissive IAM, unencrypted storage | Yes    | Both                 |
| **Open Redirect**                                  | Redirects to attacker-controlled URLs via unvalidated redirect parameters                                             | Yes    | Both                 |
| **Code Injection / Eval Injection**                | Dynamic code execution from untrusted input                                                                           | Yes    | Both                 |
| **Prototype Pollution**                            | JavaScript object prototype manipulation via untrusted key assignment                                                 | Yes    | Both                 |
| **Template Injection (SSTI)**                      | Server-side template injection via user input rendered in template engines                                            | Yes    | Both                 |
| **Insecure File Upload**                           | Unrestricted file type or content upload without validation                                                           | Yes    | Both                 |
| **Missing Security Headers**                       | CSP, HSTS, X-Frame-Options, and other protective headers absent from responses                                        | Yes    | Both                 |
| **CORS Misconfiguration**                          | Overly permissive cross-origin resource sharing allowing untrusted origins                                            | Yes    | Both                 |
| **Race Conditions / TOCTOU**                       | Time-of-check to time-of-use vulnerabilities in file and resource access                                              | Yes    | Triage               |
| **Improper Input Validation**                      | Missing or insufficient validation of input data before processing                                                    | Yes    | Both                 |
| **Integer Overflow / Underflow**                   | Arithmetic boundary condition errors leading to unexpected behavior                                                   | Yes    | Both                 |

## Secrets Detection

Pixee primarily triages secrets findings — detecting hardcoded credentials, API keys, tokens, and cloud provider secrets in source code. Automated fixes are available for common patterns where a safe remediation is unambiguous.

| Category                        | Examples                                                     |
| ------------------------------- | ------------------------------------------------------------ |
| **API Keys & Tokens**           | Hardcoded API keys, OAuth tokens, service account keys       |
| **Credentials in Code**         | Hardcoded passwords, database connection strings             |
| **Cloud Provider Secrets**      | AWS access keys, GCP service account JSON, Azure credentials |
| **Private Keys & Certificates** | RSA/EC private keys, TLS certificates committed to repos     |

## Custom Rules

Pixee's triage engine handles custom scanner rules — including custom Semgrep rules, custom CodeQL queries, and internal rule sets — through its adaptive analysis tier. Custom rules don't require Pixee configuration; the engine generates triage logic for novel rule types automatically.

## Fix Modes Explained

**Deterministic** — A pre-built codemod applies a rule-based transformation. Same input always produces the same output. Zero LLM involvement. Fastest fix path and most predictable output.

**AI** — An AI-powered fix is generated for patterns where deterministic rules do not reach — custom framework wrappers, multi-file dataflows, context-dependent sanitization, or novel vulnerability patterns. Every AI-generated fix passes through an independent quality evaluation before delivery.

**Both** — A deterministic codemod handles well-understood patterns (standard libraries, known frameworks), while AI handles custom or complex variants. Routing is automatic.

Fix mode and coverage depth vary by language and scanner. For supported languages and IaC formats, see [Language Support](/languages/overview). For per-scanner setup, see [Integrations](/integrations/overview).
