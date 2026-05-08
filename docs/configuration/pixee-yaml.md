---
title: PIXEE.yaml Reference
slug: /configuration/pixee-yaml
track: dev
content_type: reference
seo_title: PIXEE.yaml Reference -- Pixee Docs
description: Complete reference for PIXEE.yaml, the per-repository configuration file for controlling Pixee triage, fix, and ignore behavior.
sidebar_position: 2
---

# PIXEE.yaml Reference

PIXEE.yaml is a configuration file placed in the root of any repository to control Pixee's behavior for that project. It lets developers specify which findings to ignore, which directories to exclude, which fix types to enable or disable, and how PRs should be formatted. The file is version-controlled alongside your code, giving your team full ownership of Pixee's behavior in each repository.

## File Location and Format

Place a file named `PIXEE.yaml` in the root of your repository (the same directory as your `README.md` or `.gitignore`).

- **Format:** YAML (UTF-8 encoding)
- **Required:** No. Pixee works without it. Every setting has a sensible default.
- **Version-controlled:** Changes to PIXEE.yaml are tracked in git history like any other configuration file.
- **SCM support:** PIXEE.yaml is read from the repository root on GitHub, GitLab, Azure DevOps, and Bitbucket.

## Complete Schema Reference

Below is the annotated schema showing all available top-level keys.

```yaml
# PIXEE.yaml — Full annotated reference

# Exclude paths from analysis
excludes:
  paths:
    - "tests/**"
    - "docs/**"
    - "vendor/**"
    - "**/generated/**"

# Ignore specific findings
ignores:
  # Suppress by CWE category
  cwes:
    - "CWE-79"
    - "CWE-502"
  # Suppress by specific finding ID
  finding-ids:
    - "pixee:java/secure-random"

# Control which fix types are active
fixes:
  # Enable or disable entire categories
  categories:
    sast: true
    sca: false
  # Enable or disable specific codemods
  codemods:
    - name: "pixee:java/sql-parameterizer"
      enabled: true
    - name: "pixee:python/secure-flask-cookie"
      enabled: false

# PR formatting preferences
pr:
  title-prefix: "[Pixee]"
  labels:
    - "security"
    - "automated-fix"
  reviewers:
    - "security-team"
  draft: false

# Language-specific overrides
languages:
  java:
    excludes:
      paths:
        - "src/legacy/**"
  python:
    fixes:
      codemods:
        - name: "pixee:python/url-sandbox"
          enabled: false
```

### `excludes`

Controls which files and directories Pixee skips during analysis.

| Field            | Type            | Default                   | Description                                     |
| ---------------- | --------------- | ------------------------- | ----------------------------------------------- |
| `excludes.paths` | list of strings | `[]` (analyze everything) | Glob patterns for files and directories to skip |

Glob patterns follow standard syntax: `*` matches within a directory, `**` matches across directories, and `?` matches a single character.

### `ignores`

Suppresses specific findings without excluding entire paths.

| Field                 | Type            | Default | Description                                 |
| --------------------- | --------------- | ------- | ------------------------------------------- |
| `ignores.cwes`        | list of strings | `[]`    | CWE identifiers to suppress across the repo |
| `ignores.finding-ids` | list of strings | `[]`    | Specific finding identifiers to suppress    |

Use `cwes` when an entire vulnerability category is not relevant to your project (for example, CWE-79 XSS in a backend-only service). Use `finding-ids` for surgical suppression of individual findings.

### `fixes`

Controls which fix types Pixee generates.

| Field                      | Type    | Default | Description                 |
| -------------------------- | ------- | ------- | --------------------------- |
| `fixes.categories.sast`    | boolean | `true`  | Enable SAST-related fixes   |
| `fixes.categories.sca`     | boolean | `true`  | Enable SCA/dependency fixes |
| `fixes.codemods[].name`    | string  | --      | Codemod identifier          |
| `fixes.codemods[].enabled` | boolean | `true`  | Whether this codemod runs   |

Disabling a category disables all codemods in that category. Per-codemod settings override category-level settings.

### `pr`

Controls how Pixee formats the pull requests it opens.

| Field             | Type            | Default | Description                                   |
| ----------------- | --------------- | ------- | --------------------------------------------- |
| `pr.title-prefix` | string          | `""`    | Prefix prepended to PR titles                 |
| `pr.labels`       | list of strings | `[]`    | Labels applied to Pixee PRs                   |
| `pr.reviewers`    | list of strings | `[]`    | Reviewers or teams auto-assigned to Pixee PRs |
| `pr.draft`        | boolean         | `false` | Open PRs as drafts                            |

### `languages`

Applies overrides scoped to a specific language. Any key valid at the top level (`excludes`, `ignores`, `fixes`) can be nested under a language key.

| Field                       | Type   | Default            | Description                         |
| --------------------------- | ------ | ------------------ | ----------------------------------- |
| `languages.<lang>.excludes` | object | inherits top-level | Language-scoped path exclusions     |
| `languages.<lang>.fixes`    | object | inherits top-level | Language-scoped fix controls        |
| `languages.<lang>.ignores`  | object | inherits top-level | Language-scoped finding suppression |

Supported language keys: `java`, `python`, `javascript`, `typescript`, `csharp`, `go`, `php`.

## Common Configuration Recipes

### Exclude test directories

```yaml
excludes:
  paths:
    - "tests/**"
    - "__tests__/**"
    - "**/*_test.go"
    - "**/*.test.ts"
    - "**/*.spec.js"
```

Skip test files where security findings are typically non-exploitable.

### Ignore a specific CWE across the repo

```yaml
ignores:
  cwes:
    - "CWE-79"
```

Useful when your project is a backend API with no user-facing HTML, making XSS findings irrelevant.

### Disable SCA fixes, keep SAST fixes

```yaml
fixes:
  categories:
    sast: true
    sca: false
```

Keep Pixee's SAST remediation active while managing dependency updates through a separate tool (Dependabot, Renovate).

### Add team labels and reviewers to PRs

```yaml
pr:
  title-prefix: "[Security]"
  labels:
    - "security"
    - "pixee"
    - "team-platform"
  reviewers:
    - "security-team"
  draft: true
```

Auto-label and assign Pixee PRs for filtering in your PR queue. Opening as drafts gives reviewers a chance to inspect before CI runs.

### Restrict analysis to specific languages

```yaml
languages:
  java:
    fixes:
      categories:
        sast: true
        sca: true
  python:
    fixes:
      categories:
        sast: true
        sca: false
```

Combined with top-level `fixes.categories` set to `false`, this pattern restricts Pixee to specific languages.

### Suppress a single noisy finding

```yaml
ignores:
  finding-ids:
    - "pixee:java/secure-random"
```

Surgical suppression when a specific codemod triggers on code that intentionally uses a weaker pattern (for example, non-cryptographic random number generation in test data).

## Precedence Rules

1. **PIXEE.yaml overrides organization defaults** for the repository it lives in. If your org default enables SCA fixes but your repo disables them, the repo setting wins.
2. **Organization policies may restrict PIXEE.yaml.** Security teams can configure policies that PIXEE.yaml cannot override, ensuring baseline governance across all repositories.
3. **Language-scoped settings override top-level settings** within that language. A top-level `excludes` applies to all languages unless a language-specific `excludes` is defined.
4. **Invalid PIXEE.yaml falls back to org defaults.** If the file has syntax errors, Pixee ignores it, falls back to organization defaults, and logs a validation warning. No analysis is skipped.

## Validation and Troubleshooting

### Validating locally

PIXEE.yaml is standard YAML. Validate syntax before committing with any YAML linter:

```bash
# Using yamllint
yamllint PIXEE.yaml

# Using yq (quick parse check)
yq eval '.' PIXEE.yaml > /dev/null
```

### Confirming Pixee loaded your file

Check the Pixee dashboard for your repository. The configuration status indicates whether PIXEE.yaml was detected and parsed. Pixee also annotates PRs with a note when repository-level configuration is active.

### Common errors

| Symptom                               | Likely Cause                                        | Fix                                                             |
| ------------------------------------- | --------------------------------------------------- | --------------------------------------------------------------- |
| PIXEE.yaml ignored, org defaults used | YAML syntax error (bad indentation, missing quotes) | Run `yamllint` and fix reported issues                          |
| Exclusions not working                | Incorrect glob pattern                              | Test patterns locally; remember `**` matches across directories |
| Codemod still running after disabling | Codemod name typo                                   | Verify the exact codemod identifier in the Pixee dashboard      |
| Labels not appearing on PRs           | SCM permissions                                     | Ensure the Pixee integration has permission to apply labels     |

