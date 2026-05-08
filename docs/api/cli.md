---
title: Pixee CLI
slug: /api/cli
track: dev
content_type: tutorial
seo_title: "Pixee CLI | Command-Line Client for the Pixee Platform"
description: Install the Pixee CLI to authenticate against a Pixee deployment and drive the REST API from your terminal, scripts, or coding agents.
sidebar_position: 6
---

The Pixee CLI (`pixee`) is the command-line client for the Pixee platform. It authenticates against a Pixee deployment, exposes dedicated subcommands for the most common operations (listing repositories, inspecting scans, configuring workflows), and provides a generic `pixee api` passthrough for any other REST endpoint. The CLI is intended for Pixee customers — it talks _to_ a Pixee deployment, it does not run analysis or generate fixes locally. Source distribution: [github.com/pixee/pixee-cli](https://github.com/pixee/pixee-cli).

## When to Use the CLI

The CLI complements the SCM integrations (GitHub App, GitLab, Azure DevOps, Bitbucket); it does not replace them. Triage and remediation continue to run on the Pixee platform, triggered by your SCM integration. Use the CLI when you need to:

- **Query platform state from scripts.** List registered repositories, fetch scan history, inspect workflows.
- **Configure workflows from the command line.** Create, update, or delete schedule / new-scan / pull-request-scan workflows on a repository.
- **Drive the API from a coding agent.** Bundled `skills.sh`-formatted skills teach Claude Code, OpenAI Codex, and other agents how to use the CLI safely.
- **Hit any REST endpoint without writing curl.** The `pixee api` subcommand handles authentication, pagination, and HAL link traversal.

## Installation

### Homebrew (macOS and Linux)

```bash
brew tap pixee/pixee
brew install pixee
```

### Direct download

Pre-compiled binaries for `linux-x64`, `darwin-arm64`, and `windows-x64` are published as assets on every [GitHub Release](https://github.com/pixee/pixee-cli/releases/latest). Download the archive, extract `pixee`, place it on your `PATH`.

Verify:

```bash
pixee --version
```

## Authenticate

You need a Pixee API token (generated from the admin console's **API Tokens** page) and the URL of your Pixee deployment.

```bash
# Interactive login — stores token + server in a platform-appropriate config file.
pixee auth login --server https://pixee.example.com --token pixee_xxx

# Stdin form — keeps the token off the command line and out of shell history.
echo -n "$PIXEE_TOKEN" | pixee auth login --server https://pixee.example.com --token -

# Confirm.
pixee auth status
# Logged in to https://pixee.example.com as api-token
# Token: valid
```

The token is written with `0600` permissions on Unix; Windows inherits the per-user directory's NTFS ACL.

**Credential resolution.** For every subcommand except `pixee auth login`, the CLI resolves credentials in this order:

- **Token:** `PIXEE_TOKEN` env var → stored config.
- **Server:** `--server` flag → `PIXEE_SERVER` env var → stored config.

Setting `PIXEE_TOKEN` and `PIXEE_SERVER` is the standard CI/CD path — no `pixee auth login` step is required in pipelines.

## Common Commands

| Command                                                             | What It Does                                                                                         |
| ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `pixee repo list`                                                   | List repositories registered with the platform. Filter with `--name <pattern>`.                      |
| `pixee scan list --repo <name>`                                     | List scans for a repository. Filter with `--branch`, `--tool`, `--analysis-state`, `--has-analysis`. |
| `pixee scan get <id>`                                               | Fetch a single scan by UUID.                                                                         |
| `pixee workflow list --repo <name>`                                 | List workflows on a repository.                                                                      |
| `pixee workflow create schedule --repo <name> --cadence weekly ...` | Create a schedule workflow. Sibling subcommands: `new-scan`, `pull-request-scan`.                    |
| `pixee workflow update <id> ...`                                    | Update an existing workflow (partial-update semantics).                                              |
| `pixee workflow delete <id>`                                        | Remove a workflow.                                                                                   |
| `pixee api /api/v1/repositories --paginate`                         | Send an authenticated GET to any endpoint, walking pagination.                                       |
| `pixee api /api/v1/<path> --method POST --input body.json`          | POST a JSON body.                                                                                    |
| `pixee --help`                                                      | Show all available commands.                                                                         |
| `pixee <command> --help`                                            | Show command-specific flags.                                                                         |

The dedicated subcommands cover the common cases. `pixee api` is the escape hatch — use it when a dedicated subcommand does not yet exist, or when a coding agent needs to compose multi-step operations directly.

## Output Format

All subcommands accept `--output text` (default — flat, line-oriented, suitable for `grep`/`awk`) or `--output json` (machine-readable, pipe to `jq`). The `--json` shorthand is equivalent to `--output json`.

```bash
pixee repo list --json | jq '.[] | select(.type == "github") | .full_name'
```

## Exit Codes

Scripts and agents can branch on these without parsing stderr:

| Code | Meaning                                                                   |
| ---- | ------------------------------------------------------------------------- |
| 0    | Success                                                                   |
| 1    | General error                                                             |
| 2    | Authentication failure (token missing, expired, invalid, or wrong server) |
| 3    | Resource not found                                                        |

Errors from the Pixee API are returned as `application/problem+json`. With `--output text`, the CLI renders the problem document in compact human-readable form; with `--output json` the raw document passes through unchanged.

## HAL Discovery via `pixee api`

The Pixee REST API is a HAL (Hypertext Application Language) API. Every response includes `_links` to related resources. Start at `/api/v1` and follow links rather than hardcoding paths:

```bash
# Inspect the root.
pixee api /api/v1

# Follow the "repositories" link.
pixee api /api/v1/repositories --paginate

# Drill into a specific repository — its _links lead to scans, workflows, etc.
pixee api /api/v1/repositories/<id>
```

## Coding-Agent Skills

The CLI ships [skills.sh](https://skills.sh)-formatted skills that teach coding agents (Claude Code, OpenAI Codex, and others) how to drive the CLI without you re-explaining the conventions every time. Skills cover global flags and exit codes (`pixee-shared`), authentication (`pixee-auth`), the `pixee api` escape hatch (`pixee-api`), and each command group (`pixee-repo`, `pixee-scan`, `pixee-workflow`).

```bash
# Install all skills.
npx skills add pixee/pixee-cli --all

# Or pick interactively.
npx skills add pixee/pixee-cli
```

The skills are licensed separately under Apache 2.0 and live in the [`skills/`](https://github.com/pixee/pixee-cli/tree/main/skills) directory of the CLI repo.

## CLI in CI/CD

The CLI is well-suited to running inside CI: set `PIXEE_TOKEN` and `PIXEE_SERVER` as secrets, install the binary, and call any subcommand. Common patterns:

```bash
# Inspect platform state during a release pipeline.
pixee scan list --repo "$REPO" --branch main --tool codeql --json

# Create or update a workflow as part of repository provisioning.
pixee workflow create new-scan --repo "$REPO" --tool codeql ...
```

The CLI does not run analysis or generate fixes — those happen on the platform, triggered by your SCM integration. See [CI/CD Integration](/integrations/ci-cd) for the end-to-end pipeline patterns.

