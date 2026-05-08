---
title: Python
slug: /languages/python
track: both
content_type: guide
seo_title: Python Language Support -- Pixee Docs
description: "Pixee Python support: 60+ deterministic codemods and AI-powered fixes for Django, Flask, and FastAPI."
sidebar_position: 3
---

Pixee remediates Python vulnerabilities automatically using 60+ deterministic codemods and AI-powered fixes for custom patterns. Coverage includes Django, Flask, and FastAPI applications with fixes for SQL injection, SSRF, insecure deserialization (PyYAML hardening, defused XML), weak cryptography, and dependency vulnerabilities. Pixee uses full AST-level analysis for deep cross-file dataflow tracking and framework-aware transformations across all five Python packaging formats.

Python is Pixee's second-deepest language ecosystem alongside Java. The open-source [codemodder-python](https://github.com/pixee/codemodder-python) engine is publicly inspectable, and support for five packaging conventions (requirements.txt, pyproject.toml, Pipfile, setup.py, setup.cfg) sets Pixee apart from tools that handle only one. For the full language coverage matrix, see the [Language Support Overview](/languages/languages-overview).

## What Pixee Fixes in Python

| Vulnerability Type         | CWE     | Example Fix                                                 | Fix Mode      |
| -------------------------- | ------- | ----------------------------------------------------------- | ------------- |
| SQL Injection              | CWE-89  | Parameterized query conversion                              | Deterministic |
| SSRF                       | CWE-918 | URL validation and allowlist enforcement                    | Deterministic |
| Insecure Deserialization   | CWE-502 | PyYAML safe_load, defused XML parsing                       | Deterministic |
| Weak Cryptography          | CWE-327 | secrets module usage, JWT decode verification               | Deterministic |
| Path Traversal             | CWE-22  | Canonical path validation                                   | Deterministic |
| Insecure Temp Files        | CWE-377 | tempfile.mkstemp usage                                      | Deterministic |
| SSL/TLS Protocol           | CWE-326 | Protocol version enforcement                                | Deterministic |
| Cross-Site Scripting       | CWE-79  | Output encoding, template sanitization                      | Deterministic |
| Custom Framework Patterns  | Various | Framework-specific sanitization, multi-file fixes           | AI-powered    |
| Dependency Vulnerabilities | N/A     | Version upgrade across 5 manifest formats + source refactor | Hybrid        |

## Django

Django is the most common Python web framework in enterprise environments, and Pixee provides dedicated support for Django-specific security patterns.

**What Pixee understands about your Django code:**

- Django ORM query patterns and raw SQL injection risks via `extra()`, `raw()`, and `RawSQL()`
- Template injection and XSS prevention in Django templates and Jinja2
- Django settings security hardening (SECRET_KEY exposure, DEBUG mode in production, ALLOWED_HOSTS configuration)
- Django REST Framework serializer validation patterns
- Model, view, and URL configuration conventions

**Django-specific fixes include:**

- ORM injection remediation that converts raw queries to parameterized Django ORM calls
- Template XSS prevention using Django's auto-escaping and `mark_safe` audit
- Settings hardening for common misconfigurations flagged by security scanners
- REST Framework input validation tightening on serializer fields
- CSRF middleware configuration fixes

Pixee recognizes Django idioms. Fixes use Django-native security utilities (e.g., `django.utils.html.escape`, ORM parameterization) rather than introducing external libraries.

## Flask and FastAPI

**Flask:** Pixee handles Flask request handling patterns including `request.args`, `request.form`, and `request.json` input validation. Fixes for Flask applications address injection in Jinja2 templates, insecure session configuration, and debug mode exposure.

**FastAPI:** Pixee supports FastAPI's dependency injection and Pydantic validation patterns. Fixes respect FastAPI's async patterns and type-annotated request handling.

Both frameworks receive the same deterministic codemod coverage for common vulnerability types plus AI-powered MagicMods for framework-specific patterns.

## How It Works for Python

**Codemod engine:** [codemodder-python](https://github.com/pixee/codemodder-python) is an open-source engine with 60+ core codemods. Customers and auditors can inspect every transformation rule on GitHub.

**Transformer strategies:** codemodder-python uses multiple rewriting approaches. LibCST handles AST-level transformations for Python source code. Regex transformers handle configuration files. XML transformers handle manifest and config files. A single codemod can target Python source, configuration files, and dependency manifests in one pass.

**Analysis depth:** Full AST parsing via LibCST enables cross-file dataflow tracking. Pixee follows taint propagation from request handlers through business logic to database calls, understanding the full path a vulnerability travels through your Python application.

**Fix routing:** Known vulnerability patterns (SQL injection, insecure deserialization, weak cryptography) get instant, deterministic fixes. Novel or custom patterns route to AI-powered MagicMods with Python-specific context and your PIXEE.yaml configuration.

## Dependency Management

Python has the most fragmented packaging ecosystem of any language Pixee supports. Pixee handles all five conventions:

| Manifest Format  | Tool                     |
| ---------------- | ------------------------ |
| requirements.txt | pip                      |
| pyproject.toml   | Poetry, Flit, Hatch, pip |
| Pipfile          | Pipenv                   |
| setup.py         | setuptools               |
| setup.cfg        | setuptools               |

Each format has its own writer module. A single pull request contains the version bump in the correct manifest file and any downstream source-file changes required by the upgrade. If your project uses pyproject.toml with Poetry, Pixee updates pyproject.toml -- not requirements.txt.

Most tools handle only requirements.txt. Pixee handles all five, which matters for enterprise Python projects where packaging conventions vary across teams and repositories.

## Fix Examples

**Insecure Deserialization (CWE-502) -- PyYAML safe_load**

Before:

```python
import yaml

with open("config.yml") as f:
    config = yaml.load(f)
```

After:

```python
import yaml

with open("config.yml") as f:
    config = yaml.safe_load(f)
```

**SQL Injection (CWE-89) -- Django ORM Parameterization**

Before:

```python
def get_user(request):
    user_id = request.GET.get("id")
    users = User.objects.raw(
        f"SELECT * FROM auth_user WHERE id = '{user_id}'"
    )
    return render(request, "user.html", {"users": users})
```

After:

```python
def get_user(request):
    user_id = request.GET.get("id")
    users = User.objects.raw(
        "SELECT * FROM auth_user WHERE id = %s", [user_id]
    )
    return render(request, "user.html", {"users": users})
```

**Weak Cryptography (CWE-327) -- Secure Random**

Before:

```python
import random

token = ''.join(random.choice('abcdef0123456789') for _ in range(32))
```

After:

```python
import secrets

token = secrets.token_hex(16)
```

## Scanner Compatibility

| Scanner            | Python Support |
| ------------------ | -------------- |
| CodeQL             | Yes            |
| Semgrep            | Yes            |
| SonarQube          | Yes            |
| Checkmarx          | Yes            |
| Snyk Code          | Yes            |
| Bandit (via SARIF) | Yes            |
| Universal SARIF    | Yes            |

Bandit findings can be exported in SARIF format and consumed by Pixee through the [universal SARIF integration](/integrations/sarif-universal).

## Compatibility

| Dimension            | Details                                                        |
| -------------------- | -------------------------------------------------------------- |
| Packaging tools      | pip, Poetry, Pipenv, setuptools                                |
| CI/CD platforms      | GitHub Actions, GitLab CI, Azure DevOps, Bitbucket Pipelines   |
| Code hosting         | GitHub, GitLab, Azure DevOps, Bitbucket                        |
| Dependency manifests | requirements.txt, pyproject.toml, Pipfile, setup.py, setup.cfg |

