---
title: HCL AppScan Integration
slug: /integrations/scanners/appscan
track: both
content_type: guide
seo_title: HCL AppScan Integration with Pixee
description: Pixee integration with HCL AppScan for automated triage and remediation, with custom trace format handling.
sidebar_position: 1
---

# HCL AppScan Integration

Pixee integrates natively with HCL AppScan to triage SAST findings and deliver remediation as pull requests. The dedicated AppScan handler includes a custom code flow mapper that preserves AppScan's unique trace format for accurate triage decisions.

## What AppScan Detects

HCL AppScan (formerly IBM AppScan) is an enterprise application security testing suite widely deployed in financial services, insurance, and government. HCL acquired AppScan from IBM in 2019, and the product continues to serve organizations that have standardized on it for decades.

AppScan detects:

- **Static Application Security Testing (SAST)** -- source code analysis for injection flaws, cross-site scripting, authentication issues, and cryptographic weaknesses
- **Dynamic Application Security Testing (DAST)** -- runtime vulnerability scanning of web applications
- **Interactive Application Security Testing (IAST)** -- combined static and dynamic approaches
- **Software Composition Analysis (SCA)** -- open-source dependency vulnerabilities
- **API security testing**

AppScan offers on-premises (AppScan Source, AppScan Enterprise) and cloud-hosted (AppScan on Cloud) deployment models.

## How Pixee Enhances AppScan

### Triage

AppScan findings are processed through Pixee's triage pipeline with dedicated handling for AppScan's unique output format.

**Custom code flow mapper.** AppScan structures its SARIF output differently from most scanners, particularly in how it represents code traces and data flows. Pixee's AppScan handler includes a custom code flow mapper that translates AppScan's SARIF structure into the format the triage engine expects, preserving trace information that would otherwise be lost. This trace preservation is what allows the triage engine to make accurate decisions about findings that involve multi-step data flows -- which is where most false positives originate.

AppScan-specific severity levels are extracted and mapped appropriately, ensuring that the triage engine interprets each finding's risk in the context AppScan intended.

### Remediation

True positive findings receive automated code fixes delivered as pull requests. AppScan has dedicated tool-specific codemods in the remediation engine, meaning fixes are generated with awareness of the specific finding types and patterns AppScan reports.

Fixes use deterministic codemods and AI-powered fixes.

For the full list of vulnerability types Pixee triages and fixes, see [What Pixee Fixes](/platform/what-pixee-fixes).

## Setup

1. **Provision an AppScan API key** with permission to post comments on issues. The Key ID and Key Secret authorize Pixee to read findings and post triage comments back.
2. **Configure AppScan credentials** in Pixee. The fields are: AppScan Base URI (defaults to `https://cloud.appscan.com`), Key ID, Key Secret, and webhook authentication credentials. For Pixee Enterprise (Helm), values live under `platform.pixeebot.appscan.{apiKeyId, apiKeySecret, webhook.user, webhook.password}`. For embedded-cluster Enterprise, the admin console exposes these fields under **Config → Security Tool → AppScan**.
3. **Choose webhook authentication mode.** Two options:
   - **Basic Auth (recommended)** — username and password for HTTP Basic auth on inbound webhook requests. Configure the username and password in Pixee, then use them when registering the webhooks in AppScan (see below).
   - **Webhook secret (deprecated)** — a shared secret embedded in the webhook URL path. Supported but not recommended.
4. **Configure two webhooks in AppScan** (see [Webhook Configuration](#webhook-configuration) below) so AppScan notifies Pixee when scans complete and when patch requests are created.
5. **Connect your code repository** to Pixee (GitHub, GitLab, Azure DevOps, or Bitbucket — see [Source Control](/integrations/overview#source-control-coverage)).
6. **Pixee ingests AppScan findings** and processes them through the triage and remediation pipeline.
7. **Review and merge** Pixee-generated PRs in your normal development workflow.

**Prerequisites:** HCL AppScan with SAST scan results, an API key with comment-posting permissions, Pixee account with connected repository.

### Webhook Configuration

AppScan needs two webhooks pointed at your Pixee instance: one for scan-completion events, one for patch-request events. Both are created via the AppScan Webhook API on your AppScan presence server.

**Generate the Basic Auth header.** Encode the webhook user and password configured in Pixee:

```bash
echo -n "username:password" | base64
# -> dXNlcm5hbWU6cGFzc3dvcmQ=
```

Prepend `Basic ` to form the full header value (e.g., `Basic dXNlcm5hbWU6cGFzc3dvcmQ=`).

**Webhook 1 — Scan Execution Completed.** Notifies Pixee when an AppScan scan finishes:

```json
{
  "AuthorizationHeader": "Basic <base64-credentials>",
  "PresenceId": "<your-presence-id>",
  "Uri": "https://<your-pixee-server>/api/v1/integrations/appscan-default/webhooks/_/ScanExecutionCompleted/{SubjectId}",
  "Global": true,
  "AssetGroupId": "<your-asset-group-id>",
  "Event": "ScanExecutionCompleted"
}
```

**Webhook 2 — New Patch Request.** Notifies Pixee when a patch is requested:

```json
{
  "AuthorizationHeader": "Basic <base64-credentials>",
  "PresenceId": "<your-presence-id>",
  "Uri": "https://<your-pixee-server>/api/v1/integrations/appscan-default/webhooks/CreatePatch",
  "Global": true,
  "AssetGroupId": "<your-asset-group-id>",
  "Event": "NewPatchRequest",
  "RequestMethod": "POST",
  "RequestBody": "{\"patch_id\": \"{SubjectId}\"}",
  "ContentType": "application/json"
}
```

Replace the placeholders:

- `<base64-credentials>` — the Base64 string from the encoding step above
- `<your-presence-id>` — your AppScan presence server ID
- `<your-pixee-server>` — your Pixee Enterprise hostname
- `<your-asset-group-id>` — your AppScan asset group ID

For details on AppScan's webhook API, see HCL's [AppScan Webhook API Documentation](https://cloud.appscan.com/swagger/index.html#/Webhooks/Webhooks_Create).

## Common False Positive Patterns Pixee Eliminates

- **Trace-based false positives:** AppScan's SAST traces flag data flows that are actually protected by intermediate sanitization or validation -- Pixee's custom code flow mapper preserves the full trace for accurate investigation
- **Severity inflation in low-risk contexts:** AppScan assigns high severity to findings in test code, internal APIs, and admin-only endpoints; Pixee adjusts classification based on code context
- **Framework-protected patterns:** Findings in code protected by application framework security controls that AppScan's static analysis cannot resolve
- **Duplicate findings across SAST and DAST:** When teams use both AppScan SAST and DAST, the same vulnerability may appear from both testing methods; Pixee's unified pipeline helps deduplicate

See [Integrations Overview](/integrations/overview) for the full scanner coverage matrix.
