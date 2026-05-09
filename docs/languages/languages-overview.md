---
title: Language Support
slug: /languages/overview
track: both
content_type: guide
seo_title: Language Support -- Pixee Docs
description: Programming languages and IaC formats supported by Pixee for security triage and remediation.
sidebar_position: 1
---

Pixee supports a broad and growing set of languages and IaC formats. Coverage expands continuously as the platform evolves.

## Programming Languages

| Language | Common Frameworks (examples) | Common Package Managers (examples) |
|---|---|---|
| **Java** | Spring Boot, Jakarta EE, Micronaut | Maven, Gradle |
| **Python** | Django, Flask, FastAPI | pip, Poetry, Pipenv, conda, setuptools |
| **JavaScript / TypeScript / Node.js** | Express, React, Next.js, Nest.js | npm, yarn, pnpm |
| **C# / .NET** | ASP.NET Core, Blazor | NuGet |
| **Go** | Standard library, Gin, Echo | Go modules |
| **Ruby** | Rails, Sinatra | Bundler (Gemfile) |
| **PHP** | Laravel, Symfony | Composer |
| **Kotlin** | Spring Boot, Android | Maven, Gradle |
| **Rust** | | Cargo |
| **Scala** | Play, Akka | sbt, Maven |
| **Swift** | iOS/macOS | Swift Package Manager |
| **Objective-C** | iOS/macOS | CocoaPods, Carthage |
| **Groovy** | Gradle, Spring, Jenkins | Maven, Gradle |
| **Shell / Bash** | | — |
| **PowerShell** | | — |

## Infrastructure as Code

| Format | Notes |
|---|---|
| **Terraform / HCL** | Security misconfigurations, IAM policies, storage encryption, network exposure |
| **Dockerfile / Containerfile** | Running as root, insecure base images, exposed secrets in build layers |
| **Kubernetes / Helm** | Pod security contexts, RBAC misconfigurations, exposed secrets, network policies |
| **CloudFormation** | AWS resource misconfigurations, IAM, S3, security groups |
| **Ansible** | Playbook security patterns |
| **Docker Compose** | Service configuration security |

For what Pixee triages and fixes across these languages and formats, see [What Pixee Fixes](/platform/what-pixee-fixes). Pixee's architecture is designed to work across languages — if yours isn't listed, [contact the team](https://pixee.ai/demo).
