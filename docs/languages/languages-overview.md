---
title: Language Support Overview
slug: /languages/overview
track: both
content_type: guide
seo_title: Language Support Overview -- Pixee Docs
description: Pixee supports Java, Python, JavaScript/TypeScript, .NET, Go, and PHP. Coverage matrix by language, framework, and fix type.
sidebar_position: 1
---

Pixee supports six language ecosystems: Java, Python, JavaScript/TypeScript, .NET, Go, and PHP. Coverage varies by language. Java and Python have the deepest support with 120+ deterministic codemods plus AI-powered fixes for custom patterns. Each language includes framework-specific remediation (Spring Boot, Django, Express, ASP.NET) and fixes for OWASP Top 10 vulnerability categories. The coverage matrix below shows exactly what Pixee fixes in your stack.

Language support is one half of the integration picture. Pixee also integrates with [13 native scanners](/integrations/integrations-overview) across all supported languages.

## Coverage Matrix

This table shows what Pixee supports across each language ecosystem. Use it to evaluate coverage for your stack, then visit individual language pages for framework details and fix examples.

| Language                                       | Frameworks                         | Fix Types  | Deterministic Codemods | AI Fixes (MagicMods) | Analysis Depth |
| ---------------------------------------------- | ---------------------------------- | ---------- | ---------------------- | -------------------- | -------------- |
| [Java](/languages/java)                        | Spring Boot, Jakarta EE, Micronaut | SAST + SCA | 51+ core               | Yes                  | Full AST       |
| [Python](/languages/python)                    | Django, Flask, FastAPI             | SAST + SCA | 60+ core               | Yes                  | Full AST       |
| [JavaScript/TypeScript](/languages/javascript) | Express, React, Node.js            | SAST + SCA | Growing                | Yes                  | Full AST       |
| [.NET](/languages/dotnet)                      | ASP.NET Core, Blazor               | SAST + SCA | Growing                | Yes                  | Full AST       |
| [Go](/languages/go)                            | Standard library, Gin, Echo        | SAST + SCA | Growing                | Yes                  | Tree-sitter    |
| [PHP](/languages/php)                          | Laravel, Symfony                   | SAST + SCA | Growing                | Yes                  | Tree-sitter    |

**Polyglot repositories:** Pixee analyzes each language independently within a single repository and generates language-appropriate fixes. No additional configuration is required for multi-language projects.

## Vulnerability Coverage by Language

The table below maps common vulnerability categories (by CWE) to fix availability per language. Deterministic codemods provide predictable, zero-variance fixes. AI-powered MagicMods extend coverage to custom patterns, multi-file dataflows, and framework-specific code.

| Vulnerability Category     | CWE         | Java          | Python        | JS/TS            | .NET             | Go     | PHP    |
| -------------------------- | ----------- | ------------- | ------------- | ---------------- | ---------------- | ------ | ------ |
| SQL Injection              | CWE-89      | Deterministic | Deterministic | Deterministic/AI | Deterministic/AI | AI     | AI     |
| Cross-Site Scripting       | CWE-79      | Deterministic | Deterministic | Deterministic/AI | AI               | AI     | AI     |
| SSRF                       | CWE-918     | Deterministic | Deterministic | Deterministic/AI | Deterministic/AI | AI     | AI     |
| Insecure Deserialization   | CWE-502     | Deterministic | Deterministic | AI               | AI               | AI     | AI     |
| Path Traversal             | CWE-22      | Deterministic | Deterministic | Deterministic/AI | Deterministic/AI | AI     | AI     |
| Weak Cryptography          | CWE-327/328 | Deterministic | Deterministic | Deterministic/AI | Deterministic/AI | AI     | AI     |
| Insecure Temp Files        | CWE-377     | Deterministic | Deterministic | AI               | AI               | --     | --     |
| SSL/TLS Protocol           | CWE-326     | Deterministic | Deterministic | AI               | AI               | --     | --     |
| Dependency Vulnerabilities | SCA         | Hybrid        | Hybrid        | Hybrid           | Hybrid           | Hybrid | Hybrid |

"Deterministic" means a pre-built codemod handles the fix with zero LLM involvement. "AI" means a MagicMod generates a context-aware fix. "Hybrid" means dependency upgrades combine manifest changes with AI-assisted source refactoring. "--" means coverage is on the roadmap.

## How Language Support Works

Every language uses the same hybrid-intelligence architecture, but the analysis tooling and codemod depth vary by ecosystem maturity.

**Two fix modes, routed automatically:**

- **Deterministic codemods** are rule-based, language-specific code transformations. They apply OWASP/SANS security patterns with zero LLM involvement. Same input produces the same output every time. Java and Python have the deepest codemod libraries (51+ and 60+ core codemods, respectively). The open-source engines ([codemodder-java](https://github.com/pixee/codemodder-java), [codemodder-python](https://github.com/pixee/codemodder-python)) are publicly inspectable.

- **AI-powered MagicMods** handle custom framework patterns, multi-file dataflow vulnerabilities, and novel vulnerability types. MagicMods use dataflow-bounded context, per-rule knowledge base guidance, and your project-level PIXEE.yaml configuration to generate fixes that match your codebase conventions. Every AI-generated fix passes through an independent quality evaluation before reaching a pull request.

Routing is automatic. The system checks whether a deterministic codemod exists for the finding. If one does, it fires instantly at zero LLM cost. If not, a MagicMod generates a fix with the appropriate scanner-aware context.

## Analysis Depth

Pixee uses two parsing approaches depending on the language. Both produce working fixes, but analysis depth differs.

| Analysis Tier   | Languages                 | What It Means                                                                                                                                                                  |
| --------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Full AST**    | Java, Python, JS/TS, .NET | Deep abstract syntax tree parsing with cross-file dataflow analysis. Framework-aware transformations understand controller patterns, service layers, and dependency injection. |
| **Tree-sitter** | Go, PHP                   | Reliable syntax-level parsing effective for standard vulnerability patterns. Coverage is expanding. AI-powered MagicMods extend reach beyond what the parser alone covers.     |

Full AST languages benefit from deeper semantic understanding of code structure, which enables more precise deterministic codemods and richer context for AI-powered fixes. Tree-sitter languages rely more heavily on MagicMods for fix generation, with growing deterministic coverage over time.

## Dependency Management by Language

Pixee upgrades vulnerable dependencies in your manifest files and coordinates the version bump with downstream source-file refactoring in a single pull request. No "upgrade succeeded, tests broken" half-states.

| Language              | Manifest Formats                                               |
| --------------------- | -------------------------------------------------------------- |
| Java                  | pom.xml, build.gradle                                          |
| Python                | requirements.txt, pyproject.toml, Pipfile, setup.py, setup.cfg |
| JavaScript/TypeScript | package.json                                                   |
| .NET                  | .csproj, packages.config                                       |
| Go                    | go.mod                                                         |
| PHP                   | composer.json                                                  |

Python's five packaging conventions are worth calling out. Most tools handle only requirements.txt. Pixee handles all five.

## Scanner Compatibility

Pixee remediates findings from [13 native scanner integrations](/integrations/integrations-overview) plus any scanner that exports SARIF. Scanner compatibility applies across all supported languages, though individual scanner coverage depth varies by language.

| Scanner         | Java | Python | JS/TS | .NET | Go  | PHP |
| --------------- | ---- | ------ | ----- | ---- | --- | --- |
| CodeQL          | Yes  | Yes    | Yes   | Yes  | Yes | --  |
| Semgrep         | Yes  | Yes    | Yes   | Yes  | Yes | Yes |
| SonarQube       | Yes  | Yes    | Yes   | Yes  | --  | Yes |
| Checkmarx       | Yes  | Yes    | --    | Yes  | --  | Yes |
| Snyk Code       | Yes  | Yes    | Yes   | --   | Yes | --  |
| Veracode        | Yes  | --     | --    | Yes  | --  | --  |
| Fortify         | Yes  | --     | --    | Yes  | --  | --  |
| AppScan         | Yes  | --     | --    | --   | --  | --  |
| Universal SARIF | Yes  | Yes    | Yes   | Yes  | Yes | Yes |

For scanner-specific details, see the [Integrations](/integrations/integrations-overview) section.

## Roadmap

Pixee is actively expanding language coverage. Current priorities:

- **Go and PHP:** Growing deterministic codemod library and deeper framework-specific patterns
- **JavaScript/TypeScript:** Expanding Node.js server-side coverage and additional framework support
- **.NET:** Broadening ASP.NET Core patterns and legacy .NET Framework coverage

If your language or framework is not listed, [contact the team](https://pixee.ai/demo) to discuss your stack. Pixee's [universal SARIF integration](/integrations/sarif-universal) can remediate findings from any scanner in any language.

