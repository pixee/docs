---
title: .NET
slug: /languages/dotnet
track: both
content_type: guide
seo_title: .NET Language Support -- Pixee Docs
description: "Pixee .NET support: deterministic codemods and AI-powered fixes for ASP.NET Core and Blazor."
sidebar_position: 5
---

Pixee remediates .NET vulnerabilities automatically using deterministic codemods and AI-powered fixes for custom patterns. Coverage includes ASP.NET Core and Blazor applications with fixes for injection vulnerabilities, insecure cryptography, and dependency vulnerabilities. Pixee uses full AST analysis for C# source code and manages dependency upgrades across both .csproj and packages.config formats, delivering fixes as pull requests that match your codebase conventions.

.NET support uses Pixee's full AST parsing tier, providing deep cross-file analysis on par with Java and Python. Deterministic codemod coverage is growing alongside comprehensive AI-powered MagicMod support. For the full language coverage matrix, see the [Language Support Overview](/languages/overview).

## What Pixee Fixes in .NET

| Vulnerability Type         | CWE     | Example Fix                                                        | Fix Mode         |
| -------------------------- | ------- | ------------------------------------------------------------------ | ---------------- |
| SQL Injection              | CWE-89  | Parameterized query / Entity Framework Core safe patterns          | Deterministic/AI |
| Cross-Site Scripting       | CWE-79  | Output encoding, Razor view sanitization                           | AI-powered       |
| Insecure Cryptography      | CWE-327 | RNGCryptoServiceProvider, secure defaults                          | Deterministic/AI |
| SSRF                       | CWE-918 | HttpClient URL validation                                          | Deterministic/AI |
| Path Traversal             | CWE-22  | Canonical path validation                                          | Deterministic/AI |
| Dependency Vulnerabilities | N/A     | NuGet version upgrade in .csproj/packages.config + source refactor | Hybrid           |
| Custom Framework Patterns  | Various | ASP.NET-specific sanitization                                      | AI-powered       |

## ASP.NET Core

ASP.NET Core is the primary .NET web framework in modern enterprise development. Pixee provides framework-aware support for common ASP.NET Core security patterns.

**What Pixee understands about your ASP.NET Core code:**

- Controller patterns (`[ApiController]`, `[HttpGet]`, `[HttpPost]`) and action method signatures
- Middleware pipeline ordering and security middleware configuration
- ASP.NET Core Identity configuration and authentication schemes
- Entity Framework Core query patterns, including raw SQL and LINQ
- Razor view rendering and output encoding
- Dependency injection patterns and service registration

**ASP.NET Core-specific fixes include:**

- SQL injection remediation that converts raw SQL to Entity Framework Core parameterized queries
- Controller input validation hardening using model binding and `[FromBody]`/`[FromQuery]` attributes
- Identity configuration hardening (password policies, lockout settings, token lifetimes)
- Razor view XSS prevention through proper encoding and `@Html.Raw` audit
- Middleware ordering corrections where security middleware is registered after routing

## Blazor

Pixee supports Blazor Server applications with security patterns relevant to server-side component rendering. Blazor WebAssembly security considerations differ from server-side patterns; Pixee focuses on the server-side execution model where vulnerability remediation has the highest impact.

## How It Works for .NET

**Analysis depth:** Full AST parsing for C# source code. Pixee analyzes class hierarchies, interface implementations, and cross-file dataflow from controller actions through service layers to data access code.

**Fix routing:** Known vulnerability patterns receive deterministic, zero-LLM-cost fixes. Novel or custom patterns route to AI-powered MagicMods with .NET-specific context including framework detection, NuGet dependency analysis, and your PIXEE.yaml configuration.

**Dependency support:** Pixee manages vulnerable NuGet packages across both modern (.csproj with `PackageReference`) and legacy (packages.config) project formats. A single pull request contains the version bump and any required source-file refactoring.

**Scanner compatibility:** Pixee remediates .NET findings from enterprise scanners commonly used in Microsoft-stack environments.

## Fix Examples

**SQL Injection (CWE-89) -- ASP.NET Core Controller**

Before:

```csharp
[HttpGet("users")]
public IActionResult GetUser(string userId)
{
    var query = $"SELECT * FROM Users WHERE Id = '{userId}'";
    var users = _context.Users.FromSqlRaw(query).ToList();
    return Ok(users);
}
```

After:

```csharp
[HttpGet("users")]
public IActionResult GetUser(string userId)
{
    var users = _context.Users
        .FromSqlRaw("SELECT * FROM Users WHERE Id = {0}", userId)
        .ToList();
    return Ok(users);
}
```

**Dependency Upgrade -- Vulnerable NuGet Package**

Before (.csproj):

```xml
<PackageReference Include="System.Text.Json" Version="6.0.0" />
```

After (.csproj):

```xml
<PackageReference Include="System.Text.Json" Version="6.0.10" />
```

The pull request includes any source-file changes required by the version upgrade.

## Scanner Compatibility

| Scanner         | .NET Support |
| --------------- | ------------ |
| CodeQL          | Yes          |
| SonarQube       | Yes          |
| Checkmarx       | Yes          |
| Veracode        | Yes          |
| Fortify         | Yes          |
| Universal SARIF | Yes          |

Any scanner that produces SARIF output can feed .NET findings to Pixee through the [universal SARIF integration](/integrations/sarif-universal).

## Compatibility

| Dimension       | Details                                                      |
| --------------- | ------------------------------------------------------------ |
| Package manager | NuGet                                                        |
| Project formats | .csproj (PackageReference), packages.config                  |
| CI/CD platforms | GitHub Actions, GitLab CI, Azure DevOps, Bitbucket Pipelines |
| Code hosting    | GitHub, GitLab, Azure DevOps, Bitbucket                      |
| Frameworks      | ASP.NET Core, Blazor Server                                  |

## FAQ

**Does Pixee support .NET?**

Yes. Pixee remediates .NET vulnerabilities automatically using deterministic codemods and AI-powered fixes with full AST analysis for C# source code. Fixes are delivered as pull requests.

**Does Pixee work with ASP.NET Core applications?**

Yes. Pixee recognizes ASP.NET Core controllers, middleware, Entity Framework Core patterns, and Razor views for targeted security fixes. Fixes respect ASP.NET Core conventions and use framework-native security patterns.

**How does Pixee handle NuGet dependency vulnerabilities?**

Pixee upgrades vulnerable packages in .csproj and packages.config files, coordinating version bumps with required source-file changes in a single PR.

**What .NET scanners does Pixee work with?**

Pixee remediates findings from CodeQL, SonarQube, Checkmarx, Veracode, Fortify, and any SARIF-producing scanner. Enterprise .NET shops using Microsoft-stack tooling can connect through the universal SARIF integration.
