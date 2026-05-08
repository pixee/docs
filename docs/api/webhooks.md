---
title: Webhooks
slug: /api/webhooks
track: dev
content_type: reference
seo_title: Webhooks -- Pixee Docs
description: Configure Pixee webhooks for real-time notifications on fix generation, PR status, triage decisions, and remediation events.
sidebar_position: 3
---

# Webhooks

Pixee webhooks deliver real-time HTTP POST notifications when remediation events occur -- fix generated, PR opened, triage decision made, or fix merged. Configure webhook endpoints to integrate Pixee with your ticketing system, SIEM, Slack channels, or custom automation pipelines. This page documents available event types, payload schemas, authentication, retry behavior, and setup instructions.

## Event types

| Event              | Trigger                                           | Payload Includes                                                                       |
| ------------------ | ------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `fix.generated`    | A fix passes evaluation and is ready for delivery | Fix summary, finding metadata, repository, codemod ID                                  |
| `pr.opened`        | A pull request or merge request is created        | PR URL, fix summary, affected files, target branch                                     |
| `pr.merged`        | A fix PR is merged by a developer                 | PR URL, merge metadata, fix details, merge timestamp                                   |
| `pr.closed`        | A fix PR is closed without merging                | PR URL, close reason, closed-by metadata                                               |
| `triage.completed` | A finding finishes triage classification          | Finding ID, classification (TRUE_POSITIVE, FALSE_POSITIVE, WONT_FIX), evidence summary |
| `scan.completed`   | A repository scan finishes processing             | Repository, findings count, fixes generated, scan duration                             |

Subscribe to individual event types or use `*` to receive all events.

## Payload schema

Every webhook payload includes a common envelope with event-specific data nested under `data`.

### Common envelope

```json
{
  "id": "evt_a1b2c3d4e5",
  "type": "pr.merged",
  "created_at": "2026-04-25T14:30:00Z",
  "organization": "acme-corp",
  "repository": "backend-api",
  "data": {}
}
```

| Field          | Type   | Description                  |
| -------------- | ------ | ---------------------------- |
| `id`           | string | Unique event identifier      |
| `type`         | string | Event type (see table above) |
| `created_at`   | string | ISO 8601 timestamp           |
| `organization` | string | Organization slug            |
| `repository`   | string | Repository name              |
| `data`         | object | Event-specific payload       |

### fix.generated payload

```json
{
  "id": "evt_f1x2g3n4",
  "type": "fix.generated",
  "created_at": "2026-04-25T14:30:00Z",
  "organization": "acme-corp",
  "repository": "backend-api",
  "data": {
    "fix_id": "fix_9a8b7c",
    "codemod": "pixee:python/secure-random",
    "summary": "Replaced insecure random with cryptographically secure alternative",
    "files_changed": 1,
    "detection_tool": "codeql",
    "ai_generated": false,
    "finding_ids": ["py/insecure-randomness"]
  }
}
```

### pr.opened payload

```json
{
  "id": "evt_p1r2o3",
  "type": "pr.opened",
  "created_at": "2026-04-25T14:31:00Z",
  "organization": "acme-corp",
  "repository": "backend-api",
  "data": {
    "pr_url": "https://github.com/acme-corp/backend-api/pull/142",
    "pr_number": 142,
    "title": "Fix insecure randomness in token generation",
    "target_branch": "main",
    "files": ["src/auth/token_generator.py"],
    "fix_id": "fix_9a8b7c",
    "codemod": "pixee:python/secure-random"
  }
}
```

### triage.completed payload

```json
{
  "id": "evt_t1r2g3",
  "type": "triage.completed",
  "created_at": "2026-04-25T14:29:00Z",
  "organization": "acme-corp",
  "repository": "backend-api",
  "data": {
    "finding_id": "f_abc123",
    "rule_id": "py/insecure-randomness",
    "classification": "TRUE_POSITIVE",
    "severity": "high",
    "justification": "The random.random() call generates session tokens passed to authentication middleware. The value is predictable and exploitable in a network-accessible context.",
    "confidence": 0.95
  }
}
```

## Setup and configuration

### Register via API

```bash
curl -X POST \
     -H "Authorization: Bearer $PIXEE_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "url": "https://your-app.example.com/webhooks/pixee",
       "events": ["pr.merged", "triage.completed", "scan.completed"],
       "secret": "your-webhook-secret"
     }' \
     https://app.pixee.ai/api/v1/webhooks
```

### Register via dashboard

1. Navigate to **Settings > Webhooks** in the Pixee dashboard.
2. Click **Add Webhook**.
3. Enter your endpoint URL (must be HTTPS).
4. Select the event types to subscribe to.
5. Set a webhook secret for signature verification.
6. Click **Save**.

### Endpoint requirements

- HTTPS only. HTTP endpoints are rejected.
- Must respond with `2xx` within 10 seconds.
- Must accept `POST` requests with `Content-Type: application/json`.

## Webhook signature verification

Pixee signs every webhook payload with HMAC-SHA256 using your webhook secret. Verify signatures to confirm payloads originate from Pixee and have not been tampered with.

The signature is sent in the `X-Pixee-Signature` header as a hex digest.

### Verification example (Python)

```python
import hmac
import hashlib
from flask import Flask, request, abort

app = Flask(__name__)
WEBHOOK_SECRET = b"your-webhook-secret"

@app.route("/webhooks/pixee", methods=["POST"])
def handle_webhook():
    signature = request.headers.get("X-Pixee-Signature")
    if not signature:
        abort(401)

    expected = hmac.new(
        WEBHOOK_SECRET,
        request.data,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected):
        abort(401)

    event = request.json
    print(f"Received {event['type']} for {event['repository']}")

    # Process event
    return "", 200
```

### Verification example (Node.js)

```javascript
const crypto = require("crypto");
const express = require("express");
const app = express();

const WEBHOOK_SECRET = "your-webhook-secret";

app.post(
  "/webhooks/pixee",
  express.raw({ type: "application/json" }),
  (req, res) => {
    const signature = req.headers["x-pixee-signature"];
    const expected = crypto
      .createHmac("sha256", WEBHOOK_SECRET)
      .update(req.body)
      .digest("hex");

    if (
      !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))
    ) {
      return res.status(401).send("Invalid signature");
    }

    const event = JSON.parse(req.body);
    console.log(`Received ${event.type} for ${event.repository}`);
    res.sendStatus(200);
  },
);
```

## Retry behavior

When a webhook delivery fails, Pixee retries with exponential backoff:

| Attempt     | Delay      | Cumulative Time |
| ----------- | ---------- | --------------- |
| 1 (initial) | Immediate  | 0               |
| 2           | 30 seconds | 30s             |
| 3           | 2 minutes  | 2m 30s          |
| 4           | 10 minutes | 12m 30s         |
| 5           | 1 hour     | 1h 12m 30s      |

A delivery is considered failed when:

- The endpoint returns a non-`2xx` status code.
- The connection times out (10-second limit).
- DNS resolution or TLS handshake fails.

After 5 failed attempts, the delivery is marked as failed. Review failed deliveries in **Settings > Webhooks > Delivery Log**.

## Testing

Send a test event to verify your endpoint is configured correctly:

```bash
curl -X POST \
     -H "Authorization: Bearer $PIXEE_TOKEN" \
     https://app.pixee.ai/api/v1/webhooks/WEBHOOK_ID/test
```

The test event uses the `ping` type with a minimal payload:

```json
{
  "id": "evt_test_ping",
  "type": "ping",
  "created_at": "2026-04-25T14:30:00Z",
  "organization": "acme-corp",
  "repository": null,
  "data": {
    "message": "Webhook configured successfully"
  }
}
```

## Integration patterns

### Slack notification on fix merged

```python
import requests
from flask import Flask, request

SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T00/B00/xxx"

@app.route("/webhooks/pixee", methods=["POST"])
def handle_webhook():
    event = request.json

    if event["type"] == "pr.merged":
        requests.post(SLACK_WEBHOOK_URL, json={
            "text": f":white_check_mark: Fix merged in *{event['repository']}*\n"
                    f"<{event['data']['pr_url']}|{event['data']['title']}>"
        })

    return "", 200
```

### Jira ticket on triage completion

```python
if event["type"] == "triage.completed":
    data = event["data"]
    if data["classification"] == "TRUE_POSITIVE" and data["severity"] == "critical":
        # Create Jira ticket for critical true positives
        jira.create_issue(
            project="SEC",
            summary=f"Critical finding: {data['rule_id']} in {event['repository']}",
            description=data["justification"],
            priority="High"
        )
```

## Related pages

- [API Overview](/api/api-overview) -- Authentication and endpoint reference
- [SARIF Reference](/api/sarif) -- Input format that triggers scan events
- [CI/CD Integration](/integrations/ci-cd) -- Common webhook consumer patterns
- [Changelog](/api/changelog) -- Webhook event version history
