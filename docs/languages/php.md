---
title: PHP
slug: /languages/php
track: both
content_type: guide
seo_title: PHP Language Support -- Pixee Docs
description: "Pixee PHP support: Tree-sitter analysis and AI-powered fixes for Laravel and Symfony applications."
sidebar_position: 7
---

Pixee remediates PHP vulnerabilities using Tree-sitter-based analysis and AI-powered fixes for Laravel and Symfony applications. Coverage includes injection vulnerabilities, insecure cryptography, and dependency vulnerabilities managed through Composer. PHP support uses Tree-sitter parsing with expanding deterministic coverage and AI-powered fixes for custom framework patterns. Fixes are delivered as pull requests that match your codebase conventions.

PHP powers significant enterprise web infrastructure through Laravel, Symfony, and WordPress. Pixee's PHP support ensures teams running these frameworks have automated remediation in their pipeline. For the full language coverage matrix, see the [Language Support Overview](/languages/overview).

## What Pixee Fixes in PHP

| Vulnerability Type         | CWE     | Example Fix                                 | Fix Mode   |
| -------------------------- | ------- | ------------------------------------------- | ---------- |
| SQL Injection              | CWE-89  | Parameterized queries via PDO               | AI-powered |
| Cross-Site Scripting       | CWE-79  | Output encoding, htmlspecialchars           | AI-powered |
| Insecure Deserialization   | CWE-502 | Safe unserialize patterns                   | AI-powered |
| Path Traversal             | CWE-22  | realpath validation                         | AI-powered |
| Insecure Cryptography      | CWE-327 | random_bytes, sodium functions              | AI-powered |
| Dependency Vulnerabilities | N/A     | Composer version upgrades + source refactor | Hybrid     |
| Custom Framework Patterns  | Various | Framework-specific sanitization             | AI-powered |

PHP fixes are primarily AI-powered through MagicMods, with growing deterministic coverage. MagicMods receive PHP-specific context including framework detection, Composer dependency analysis, and your PIXEE.yaml configuration.

## Laravel and Symfony

**Laravel:** Pixee recognizes Laravel-specific patterns and provides targeted fixes:

- Eloquent ORM injection prevention (raw queries, `whereRaw`, `DB::select` with string interpolation)
- Laravel middleware security patterns and authentication guard configuration
- Blade template XSS prevention and `{!! !!}` unescaped output audit
- Mass assignment protection (`$fillable`, `$guarded` configuration)
- CSRF token verification and session configuration hardening

**Symfony:** Pixee supports Symfony security component patterns including:

- Doctrine DBAL and ORM query parameterization
- Twig template output encoding
- Security voter and access control patterns
- Symfony form validation and input sanitization

## How It Works for PHP

**Analysis approach:** Pixee uses Tree-sitter for PHP source code parsing. Tree-sitter provides reliable syntax-level analysis effective for identifying standard vulnerability patterns in PHP applications.

**Comparison to full AST languages:** Like Go, PHP uses Tree-sitter rather than full AST parsing. This means lighter cross-file analysis compared to Java, Python, JavaScript/TypeScript, and .NET. AI-powered MagicMods compensate by providing deep, context-aware fixes for complex patterns. Deterministic codemod coverage is expanding.

**Dependency support:** Pixee manages vulnerable packages in composer.json and composer.lock. A single pull request contains the version bump and any source-file refactoring required by the upgrade.

**Scanner compatibility:** Pixee remediates PHP findings from common scanners used in PHP development environments.

## Fix Example

**SQL Injection (CWE-89) -- PDO Parameterization**

Before:

```php
$userId = $_GET['id'];
$stmt = $pdo->query("SELECT * FROM users WHERE id = '$userId'");
$user = $stmt->fetch();
```

After:

```php
$userId = $_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$userId]);
$user = $stmt->fetch();
```

## Scanner Compatibility

| Scanner         | PHP Support |
| --------------- | ----------- |
| Semgrep         | Yes         |
| SonarQube       | Yes         |
| Checkmarx       | Yes         |
| Universal SARIF | Yes         |

Any scanner that produces SARIF output can feed PHP findings to Pixee through the [universal SARIF integration](/integrations/sarif-universal).

## Compatibility

| Dimension            | Details                                                      |
| -------------------- | ------------------------------------------------------------ |
| Package manager      | Composer                                                     |
| Dependency manifests | composer.json, composer.lock                                 |
| CI/CD platforms      | GitHub Actions, GitLab CI, Azure DevOps, Bitbucket Pipelines |
| Code hosting         | GitHub, GitLab, Azure DevOps, Bitbucket                      |
| Frameworks           | Laravel, Symfony                                             |

