---
title: API Overview
slug: /api/overview
track: dev
content_type: reference
seo_title: API Overview -- Pixee Docs
description: "Pixee REST API reference: authentication, endpoints, rate limits, and SARIF input format."
sidebar_position: 1
---

# API Overview

Pixee provides a REST API for programmatic access to vulnerability triage and remediation workflows. The API enables querying fix status, managing repository configurations, consuming webhook events for CI/CD integration, and ingesting SARIF scanner output. Authentication uses organization-scoped API tokens. This page covers available endpoints, authentication, rate limits, and links to detailed specifications.

## API architecture

The Pixee API follows standard REST conventions:

- **Protocol:** HTTPS only. All requests must use TLS.
- **Format:** JSON request and response bodies. Responses include standard HTTP status codes.
- **Base URL:** `https://app.pixee.ai/api/v1`
- **Versioning:** Path-based (`/v1/`). Breaking changes ship under a new version prefix.

## Authentication

Pixee uses bearer tokens for API authentication. Tokens are scoped to your organization and generated from the Pixee dashboard.

**Generate a token:**

1. Navigate to **Settings > API Tokens** in the Pixee dashboard.
2. Click **Create Token**.
3. Name the token and select the scope (organization-wide or repository-specific).
4. Copy the token immediately. It is displayed only once.

**Include the token in every request:**

```bash
curl -H "Authorization: Bearer YOUR_API_TOKEN" \
     https://app.pixee.ai/api/v1/repositories
```

```python
import requests

headers = {"Authorization": "Bearer YOUR_API_TOKEN"}
response = requests.get(
    "https://app.pixee.ai/api/v1/repositories",
    headers=headers
)
repositories = response.json()
```

**Token best practices:**

- Rotate tokens every 90 days.
- Use repository-scoped tokens for CI/CD pipelines that operate on a single repository.
- Store tokens in your secrets manager (Vault, AWS Secrets Manager, GitHub Actions secrets). Never commit tokens to source control.

## Rate limits

| Tier       | Requests per minute | Burst |
| ---------- | ------------------- | ----- |
| Standard   | 60                  | 10    |
| Enterprise | 300                 | 50    |

Rate-limited responses return `429 Too Many Requests` with a `Retry-After` header indicating seconds until the next available request window.

## Available endpoints

| Category     | Method   | Endpoint                      | Description                                      |
| ------------ | -------- | ----------------------------- | ------------------------------------------------ |
| Repositories | `GET`    | `/repositories`               | List repositories connected to your organization |
| Repositories | `GET`    | `/repositories/{id}`          | Get repository configuration and status          |
| Repositories | `PATCH`  | `/repositories/{id}`          | Update repository settings                       |
| Fixes        | `GET`    | `/repositories/{id}/fixes`    | List fix results for a repository                |
| Fixes        | `GET`    | `/fixes/{id}`                 | Get fix details including diff and rationale     |
| Scans        | `GET`    | `/repositories/{id}/scans`    | List scan history                                |
| Scans        | `POST`   | `/repositories/{id}/scans`    | Trigger a new scan                               |
| Triage       | `GET`    | `/repositories/{id}/findings` | List triaged findings                            |
| Triage       | `GET`    | `/findings/{id}`              | Get finding details and triage classification    |
| Webhooks     | `POST`   | `/webhooks`                   | Register a webhook endpoint                      |
| Webhooks     | `GET`    | `/webhooks`                   | List registered webhooks                         |
| Webhooks     | `DELETE` | `/webhooks/{id}`              | Remove a webhook                                 |

For webhook event types and payload schemas, see [Webhooks](/api/webhooks).

## Error handling

All error responses use a consistent JSON structure:

```json
{
  "error": {
    "code": "not_found",
    "message": "Repository with ID 'abc123' not found.",
    "request_id": "req_7f8a9b2c"
  }
}
```

| Status code | Meaning                                                                                             |
| ----------- | --------------------------------------------------------------------------------------------------- |
| `400`       | Bad request. Check request body and parameters.                                                     |
| `401`       | Invalid or missing API token.                                                                       |
| `403`       | Token does not have permission for this resource.                                                   |
| `404`       | Resource not found.                                                                                 |
| `429`       | Rate limit exceeded. Retry after the interval in the `Retry-After` header.                          |
| `500`       | Internal server error. Retry with exponential backoff. Include the `request_id` in support tickets. |

## Quick start

List your repositories and retrieve recent fix results in two calls:

```bash
# 1. List repositories
curl -s -H "Authorization: Bearer $PIXEE_TOKEN" \
     https://app.pixee.ai/api/v1/repositories | jq '.data[].name'

# 2. Get fixes for a repository
curl -s -H "Authorization: Bearer $PIXEE_TOKEN" \
     https://app.pixee.ai/api/v1/repositories/REPO_ID/fixes | jq '.data[:3]'
```

```python
import requests

TOKEN = "YOUR_API_TOKEN"
BASE = "https://app.pixee.ai/api/v1"
headers = {"Authorization": f"Bearer {TOKEN}"}

# List repositories
repos = requests.get(f"{BASE}/repositories", headers=headers).json()
repo_id = repos["data"][0]["id"]

# Get recent fixes
fixes = requests.get(
    f"{BASE}/repositories/{repo_id}/fixes",
    headers=headers,
    params={"limit": 5}
).json()

for fix in fixes["data"]:
    print(f"{fix['codemod']} - {fix['status']} - {fix['pr_url']}")
```

## Input format

Pixee consumes scanner output in **SARIF** -- the OASIS standard for static analysis results -- from 13 native scanner integrations and any SARIF-producing tool. See the [SARIF Reference](/api/sarif).

## SDKs and OpenAPI specification

An OpenAPI 3.0 specification is available for generating client libraries in any language:

```bash
curl -o pixee-openapi.json \
     https://app.pixee.ai/api/v1/openapi.json
```

Use the specification with standard code generators:

```bash
# Python client
openapi-python-client generate --path pixee-openapi.json

# TypeScript client
npx @openapitools/openapi-generator-cli generate \
    -i pixee-openapi.json -g typescript-fetch
```

## Related pages

- [SARIF Reference](/api/sarif) -- How Pixee consumes SARIF from scanners
- [Webhooks](/api/webhooks) -- Event-driven integration for CI/CD and automation
- [Changelog](/api/changelog) -- API version history and release notes
- [CI/CD Integration](/integrations/ci-cd) -- Common API consumer patterns
- [Configuration Overview](/configuration/config-overview) -- Repository management
