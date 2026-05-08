---
title: What Pixee Fixes
slug: /platform/what-pixee-fixes
track: both
content_type: reference
seo_title: "What Pixee Fixes | Vulnerability Types, Triage, and Fix Modes"
description: Canonical reference for all vulnerability types, finding categories, and fix modes Pixee handles across SAST, SCA, and IaC findings.
sidebar_position: 3
---

This page is the canonical reference for what Pixee can triage and fix. It covers all vulnerability types and finding categories across SAST, SCA, and IaC findings, and shows the fix mode (Deterministic, AI, or Both) for each category.

## Vulnerability Coverage Table

| Vulnerability Category | Examples | Triage | Fix Mode |
|---|---|---|---|
| **Injection — SQL** | SQL injection via string concatenation, unparameterized queries | Yes | Deterministic / Both |
| **Injection — Command** | OS command injection, shell metacharacters in exec calls | Yes | Deterministic / Both |
| **Injection — LDAP** | LDAP injection via unsanitized directory search filters | Yes | AI |
| **Injection — XPath** | XPath injection via user-controlled node selection | Yes | AI |
| **Injection — NoSQL** | NoSQL injection in MongoDB, Redis, and similar query patterns | Yes | AI |
| **Injection — Expression Language** | EL/OGNL injection via template or framework evaluation | Yes | AI |
| **Cross-Site Scripting (XSS) — Reflected** | Reflected XSS via unencoded user input in HTTP responses | Yes | Deterministic / Both |
| **Cross-Site Scripting (XSS) — Stored** | Stored XSS persisted in database and rendered to other users | Yes | Both |
| **Cross-Site Scripting (XSS) — DOM-Based** | DOM XSS via document.write, innerHTML, eval with user data | Yes | Both |
| **Path Traversal** | Directory traversal via `../` sequences, file inclusion flaws | Yes | Deterministic / Both |
| **Server-Side Request Forgery (SSRF)** | SSRF via unvalidated URL parameters to internal or cloud metadata endpoints | Yes | Deterministic / Both |
| **Insecure Deserialization** | Unsafe Java ObjectInputStream, Python pickle, .NET BinaryFormatter | Yes | Both |
| **Weak Cryptography** | MD5, SHA-1 for security-sensitive operations; ECB mode; short key lengths | Yes | Deterministic / Both |
| **Insecure Randomness** | `java.util.Random`, `Math.random()`, `random.random()` for security tokens | Yes | Deterministic / Both |
| **Hardcoded Secrets** | Hardcoded API keys, passwords, tokens in source code | Yes | AI |
| **Authentication / Session Weaknesses** | Broken authentication, session fixation, missing session invalidation, insecure cookie flags | Yes | Both |
| **Insecure Direct Object Reference (IDOR)** | Missing authorization checks on resource identifiers | Yes | AI |
| **XML / XXE Vulnerabilities** | XML External Entity injection, DTD processing, XXE via SSRF | Yes | Deterministic / Both |
| **Insecure Temp Files** | Predictable temp file creation, race conditions on tempfile usage | Yes | Deterministic / Both |
| **Logging Sensitive Data** | PII, credentials, tokens written to logs | Yes | AI |
| **Security Misconfigurations** | Missing security headers, insecure defaults, disabled CSRF protection | Yes | Both |
| **SSL/TLS Weaknesses** | Disabled hostname verification, accepting all certificates, weak protocols | Yes | Deterministic / Both |
| **Dependency Vulnerabilities (SCA)** | CVEs in direct and transitive open-source dependencies | Yes | Deterministic (version bumps + source refactoring) |
| **Container / Dockerfile Misconfigurations** | Running as root, insecure base image patterns, exposed secrets in layers | Yes | Both |
| **Infrastructure as Code (IaC) Misconfigurations** | Terraform / CloudFormation / Kubernetes / Helm security misconfigurations, overly permissive IAM, unencrypted storage | Yes | Both |

## Fix Modes Explained

**Deterministic** — A pre-built codemod applies a rule-based transformation. Same input always produces the same output. Zero LLM involvement. Fastest fix path and most predictable output.

**AI (MagicMod)** — An AI-powered fix is generated for patterns where deterministic rules do not reach — custom framework wrappers, multi-file dataflows, context-dependent sanitization, or novel vulnerability patterns. Every AI-generated fix passes through an independent quality evaluation before delivery.

**Both** — A deterministic codemod handles well-understood patterns (standard libraries, known frameworks), while AI handles custom or complex variants. Routing is automatic.

## Notes on Coverage

Fix mode depends on the language and scanner context. Not every vulnerability type has a deterministic codemod for every language. Java and Python have the deepest deterministic codemod libraries. Go and PHP rely more heavily on AI-powered fixes.

For per-language coverage depth, see [Language Support](/languages/overview) for the full coverage matrix across all supported languages and IaC formats.

For per-scanner handling details, see the scanner integration pages under [Integrations](/integrations/overview).
