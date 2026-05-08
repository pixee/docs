---
title: Java
slug: /languages/java
track: both
content_type: guide
seo_title: Java Language Support -- Pixee Docs
description: "Pixee Java support: 51+ deterministic codemods and AI-powered fixes for Spring Boot, Jakarta EE, and Micronaut."
sidebar_position: 2
---

Pixee remediates Java vulnerabilities automatically using 51+ deterministic codemods and AI-powered fixes for custom patterns. Coverage spans Spring Boot, Jakarta EE, and Micronaut applications with fixes for SQL injection, SSRF, insecure deserialization, weak cryptography, and dependency vulnerabilities. Pixee analyzes Java source code using full AST parsing for deep cross-file dataflow analysis, delivering fixes as pull requests.

Java is Pixee's most mature language ecosystem. The open-source [codemodder-java](https://github.com/pixee/codemodder-java) engine is publicly inspectable, and deterministic codemods cover the broadest range of vulnerability types. For the full language coverage matrix, see the [Language Support Overview](/languages/languages-overview).

## What Pixee Fixes in Java

| Vulnerability Type         | CWE     | Example Fix                                               | Fix Mode      |
| -------------------------- | ------- | --------------------------------------------------------- | ------------- |
| SQL Injection              | CWE-89  | Parameterized query conversion                            | Deterministic |
| SSRF                       | CWE-918 | URL validation and allowlist enforcement                  | Deterministic |
| Insecure Deserialization   | CWE-502 | Safe deserialization wrappers                             | Deterministic |
| Weak Cryptography          | CWE-327 | SecureRandom replacement, JWT verification hardening      | Deterministic |
| Path Traversal             | CWE-22  | Canonical path validation                                 | Deterministic |
| Insecure Temp Files        | CWE-377 | Secure temp file creation                                 | Deterministic |
| SSL/TLS Protocol           | CWE-326 | Protocol version upgrade                                  | Deterministic |
| Cross-Site Scripting       | CWE-79  | Output encoding, template sanitization                    | Deterministic |
| Custom Framework Patterns  | Various | Framework-specific sanitization, multi-file fixes         | AI-powered    |
| Dependency Vulnerabilities | N/A     | Version upgrade in pom.xml/build.gradle + source refactor | Hybrid        |

"Deterministic" fixes use pre-built codemods with zero LLM involvement. "AI-powered" fixes use MagicMods with dataflow-bounded context. "Hybrid" dependency fixes combine manifest changes with AI-assisted source refactoring.

## Spring Boot

Spring Boot applications represent the most common Java framework Pixee encounters in production. Pixee provides deep, framework-aware support:

**What Pixee understands about your Spring Boot code:**

- Spring Security configuration patterns and common misconfigurations
- Controller annotations (`@RestController`, `@RequestMapping`, `@GetMapping`) and request handler patterns
- Service layer conventions, including `@Service` and `@Repository` injection
- Spring Data JPA query patterns and JPQL injection risks
- Spring Boot dependency management across both pom.xml and build.gradle

**Spring-specific fixes include:**

- SQL injection remediation that uses Spring Data parameterized queries rather than raw JDBC
- Security configuration hardening for CSRF protection, session management, and authentication filters
- Dependency upgrades coordinated through Spring Boot's managed dependency versions (BOM alignment)
- Serialization fixes that respect Jackson configuration and Spring's `@JsonProperty` conventions

Pixee recognizes Spring Boot idioms. Fixes use your existing Spring Security configurations and preferred libraries rather than introducing unfamiliar patterns.

## Jakarta EE and Micronaut

**Jakarta EE:** Pixee handles servlet-based vulnerability patterns including `HttpServletRequest` input validation, JSP/JSTL output encoding, and JNDI injection prevention. Jakarta EE dependency management follows the same pom.xml/build.gradle workflow as Spring Boot applications.

**Micronaut:** Pixee supports Micronaut controller patterns and injection-based request handling. Micronaut applications benefit from the same deterministic codemod library as other Java frameworks, with AI-powered MagicMods extending coverage to Micronaut-specific patterns.

## How It Works for Java

**Codemod engine:** [codemodder-java](https://github.com/pixee/codemodder-java) is an open-source engine with 51+ core codemods. The engine uses full AST parsing for precise, structure-aware transformations. Customers and auditors can inspect every transformation rule on GitHub.

**Analysis depth:** Full abstract syntax tree parsing enables cross-file dataflow tracking. Pixee follows taint propagation from request handlers through service layers to data access code, understanding the full path a vulnerability travels.

**Fix routing:** When a scanner finding arrives, Pixee checks for a matching deterministic codemod. Known patterns (SQL injection parameterization, SSRF prevention, insecure deserialization) get instant, zero-LLM-cost fixes. Novel or custom patterns route to AI-powered MagicMods, which receive dataflow-bounded context and Java-specific knowledge base guidance.

**Dependency support:** Pixee manages vulnerable dependencies in both pom.xml (Maven) and build.gradle (Gradle). A single pull request contains the version bump and any required source-file refactoring. No "upgrade the library, break the build" half-states.

## Fix Examples

**SQL Injection (CWE-89) -- Parameterized Query Conversion**

Before:

```java
String query = "SELECT * FROM users WHERE id = '" + userId + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

After:

```java
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setString(1, userId);
ResultSet rs = stmt.executeQuery();
```

**Insecure Deserialization (CWE-502) -- Safe Deserialization**

Before:

```java
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();
```

After:

```java
ObjectInputFilter filter = ObjectInputFilter.Config
    .createFilter("java.base/*;!*");
ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setObjectInputFilter(filter);
Object obj = ois.readObject();
```

**Dependency Upgrade -- Vulnerable Library Version Bump**

Before (pom.xml):

```xml
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.13.1</version>
</dependency>
```

After (pom.xml):

```xml
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.13.5</version>
</dependency>
```

The accompanying pull request includes any source-file changes required by the version upgrade (updated method signatures, renamed classes, deprecated API replacements).

## Scanner Compatibility

Pixee remediates Java findings from a broad set of scanners. Java is the most widely supported language across enterprise SAST tools, and Pixee matches that breadth.

| Scanner         | Java Support |
| --------------- | ------------ |
| CodeQL          | Yes          |
| Semgrep         | Yes          |
| SonarQube       | Yes          |
| Checkmarx       | Yes          |
| Snyk Code       | Yes          |
| Veracode        | Yes          |
| Fortify         | Yes          |
| AppScan         | Yes          |
| Universal SARIF | Yes          |

Any scanner that produces SARIF output can feed Java findings to Pixee through the [universal SARIF integration](/integrations/sarif-universal).

## Compatibility

| Dimension            | Details                                                      |
| -------------------- | ------------------------------------------------------------ |
| Build tools          | Maven, Gradle                                                |
| CI/CD platforms      | GitHub Actions, GitLab CI, Azure DevOps, Bitbucket Pipelines |
| Code hosting         | GitHub, GitLab, Azure DevOps, Bitbucket                      |
| Dependency manifests | pom.xml, build.gradle                                        |

