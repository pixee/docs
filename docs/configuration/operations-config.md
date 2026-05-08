---
title: Operations Configuration
slug: /configuration/operations
track: both
content_type: guide
seo_title: Operations Configuration -- Pixee Docs
description: Configure Pixee scheduling, notifications (Slack, email, webhooks), and reporting. Control analysis timing, alert routing, and metric exports.
sidebar_position: 4
---

# Operations Configuration

This page covers three operational areas: when Pixee runs analysis (scheduling), how your team hears about results (notifications), and how you track outcomes (reporting).

## Scheduling

Pixee can analyze code on every new scanner finding, on a fixed schedule, or on demand. By default, Pixee runs analysis when new findings are available from connected scanners. Customize scheduling to align with your team's development cadence -- running analysis during off-hours, batching PRs for weekly review, or triggering analysis only on specific branches.

### Trigger Modes

| Mode                       | How It Works                                    | Best For                                                  |
| -------------------------- | ----------------------------------------------- | --------------------------------------------------------- |
| **Event-driven** (default) | Pixee analyzes when new scanner findings arrive | Teams that want immediate feedback on new vulnerabilities |
| **Scheduled**              | Pixee analyzes on a cron schedule you define    | Teams that prefer batched PRs at predictable times        |
| **On-demand**              | Trigger analysis via the dashboard or API       | POC evaluations, testing, or ad-hoc analysis              |

Event-driven is the default and requires no configuration. Pixee watches for new SARIF uploads and native scanner results, then runs Triage Automation and Remediation Automation as findings arrive.

### Cron Schedules

Set a cron expression per repository or organization to control when Pixee runs analysis. Standard cron syntax is supported:

```
# Every weekday at 2:00 AM UTC
0 2 * * 1-5

# Every Monday at 6:00 AM UTC
0 6 * * 1

# Every 6 hours
0 */6 * * *
```

Configure schedules in the Pixee dashboard under repository or organization settings.

### Timezone

Cron schedules use UTC by default. Set a timezone in the dashboard to align schedules with your team's working hours.

### Branch Filtering

By default, Pixee analyzes findings from all branches. Restrict analysis to specific branches (for example, `main`, `develop`, or release branches) to focus on production-relevant code.

### PR Timing and Batching

Scheduling affects when PRs appear in your team's queue.

- **Event-driven mode** creates PRs as soon as analysis completes. Expect PRs shortly after scanner findings arrive.
- **Scheduled mode** batches all findings discovered during the analysis window into PRs created at the scheduled time.
- **On-demand mode** creates PRs immediately after the manually triggered analysis completes.

**Avoiding PR storms.** If Pixee discovers many findings during a scheduled run, it may open several PRs at once. To manage this:

- Use PR labels (configured in [PIXEE.yaml](/configuration/pixee-yaml)) to filter Pixee PRs in your queue.
- Schedule analysis for off-hours so PRs are ready for review at the start of the workday.
- Set notification filters to surface only high-severity fixes. See [Notifications](#notifications) below.

### Enterprise Scheduling

Self-hosted Pixee deployments have additional scheduling considerations:

- **Maintenance windows.** Schedule analysis outside your cluster's maintenance windows to avoid resource contention.
- **Concurrency controls.** Large deployments can configure how many repositories are analyzed concurrently to balance throughput with infrastructure load.
- **Monitoring.** Use the bundled observability stack to track analysis duration and queue depth. See [Enterprise > Observability](/enterprise/observability) for details.

## Notifications

Pixee delivers notifications through your existing communication channels -- SCM-native notifications (PR comments, status checks), Slack, email, and webhooks. Most teams use the default SCM notifications and add Slack for security team visibility. Configure notification routing so the right people see the right events without creating alert fatigue.

### Notification Channels

| Channel        | Events                                      | Configuration                                         |
| -------------- | ------------------------------------------- | ----------------------------------------------------- |
| **SCM-native** | PR created, status checks, review comments  | Automatic via your SCM integration -- no setup needed |
| **Slack**      | New fixes, triage summaries, weekly digests | Connect the Slack App or provide a webhook URL        |
| **Email**      | Digest summaries, critical alerts           | Per-user or team email addresses in the dashboard     |
| **Webhooks**   | All events (for custom integrations)        | Webhook URL with optional secret for verification     |

SCM-native notifications are always active. Pixee PRs appear in your normal PR queue, status checks integrate with your CI pipeline, and PR comments provide triage context. No additional configuration is required for this channel.

### Configuring Slack

Connect Pixee to Slack to notify your security team when new fixes are available, triage results are ready, or weekly digests are generated.

**Setup:**

1. In the Pixee dashboard, navigate to notification settings.
2. Connect the Slack App or provide an incoming webhook URL for your target channel.
3. Select which event types to route to the channel.

**Filtering options:**

- **By severity:** Notify only on critical and high-severity findings, or include medium and low.
- **By repository:** Route different repositories to different Slack channels.
- **By fix type:** Separate SAST fix notifications from SCA dependency updates.

Per-repository Slack routing is useful for large organizations where different teams own different services.

### Email

Email notifications deliver digest summaries and critical alerts to individual users or team distribution lists.

| Setting    | Options                                                           |
| ---------- | ----------------------------------------------------------------- |
| Frequency  | Per-event, daily digest, weekly digest                            |
| Scope      | All repositories, specific repositories, specific severity levels |
| Recipients | Individual email addresses or team distribution lists             |

Configure email preferences per-user in the Pixee dashboard. Each team member can choose their own notification frequency and scope.

### Webhooks

Webhooks send event payloads to any HTTP endpoint, enabling integration with PagerDuty, ServiceNow, Jira, or custom dashboards.

**Configuration:**

- Provide a webhook URL in the Pixee dashboard.
- Optionally configure a shared secret for payload verification.
- Select which event types trigger the webhook.

Webhook payloads are JSON-formatted. For the full payload specification, see [API > Webhooks](/api/webhooks).

**Common integrations:**

| System            | Use Case                                            |
| ----------------- | --------------------------------------------------- |
| Jira              | Auto-create tickets for high-severity findings      |
| ServiceNow        | Feed remediation data into ITSM workflows           |
| PagerDuty         | Alert on-call teams for critical vulnerabilities    |
| Custom dashboards | Aggregate Pixee data alongside other security tools |

### Reducing Notification Noise

The goal is signal, not volume. Teams running Pixee at scale use these strategies:

- **Severity filtering.** Notify on critical and high findings immediately; batch medium and low findings into daily or weekly digests.
- **Per-repository overrides.** High-traffic repositories get digest-only notifications. Production-critical repos get per-event alerts.
- **Channel separation.** Route developer-facing notifications (PR events) through SCM-native channels. Route security-team notifications (triage summaries, compliance digests) through Slack or email.
- **Webhook filtering.** When using webhooks, filter by event type at the source to avoid processing irrelevant payloads downstream.

## Reporting

Pixee tracks every triage decision and remediation outcome, giving your team visibility into what was analyzed, what was fixed, and what remains. Use built-in reports for day-to-day monitoring, export data for compliance evidence, or connect to external dashboards via the API.

### Available Reports and Metrics

| Report                   | What It Shows                                                            | Who Uses It                                                  |
| ------------------------ | ------------------------------------------------------------------------ | ------------------------------------------------------------ |
| **Triage Summary**       | Findings classified by outcome: true positive, false positive, won't fix | Security leads reviewing triage quality                      |
| **Fix Activity**         | PRs created, merged, closed, and pending review                          | Developers and security leads tracking remediation progress  |
| **Merge Rate**           | Percentage of Pixee PRs merged by developers                             | Management and security leads measuring developer acceptance |
| **Remediation Velocity** | Time from finding to merged fix                                          | Compliance teams tracking MTTR reduction                     |
| **Repository Status**    | Per-repo analysis state, last scan time, recent activity                 | Developers checking individual repo health                   |

**Merge rate** is the percentage of Pixee PRs that developers review and merge. It is a primary indicator of fix quality and relevance. See [Fix Safety](/how-it-works/fix-safety) for production metrics.

**Remediation velocity** measures the elapsed time from when a finding is detected to when its fix is merged. This metric maps directly to Mean Time to Remediation (MTTR), a standard compliance metric.

**Triage volume** tracks how many findings Pixee classified, broken down by true positive, false positive, and won't-fix outcomes. See [Triage Engine](/how-it-works/triage-engine) for details on false positive reduction.

### Dashboard

The Pixee dashboard provides real-time visibility into triage and remediation activity across your organization.

**Filtering options:**

| Filter     | Options                                            |
| ---------- | -------------------------------------------------- |
| Repository | Single repo, multiple repos, or all repos          |
| Time range | Last 7 days, 30 days, 90 days, custom range        |
| Severity   | Critical, High, Medium, Low                        |
| Language   | Java, Python, JavaScript/TypeScript, .NET, Go, PHP |

**Trend views** show how metrics change over time. Track merge rate improvement as your team builds confidence, watch triage volume decrease as false positives are eliminated, and monitor remediation velocity across releases.

### Exporting Data

| Format   | Use Case                                                         |
| -------- | ---------------------------------------------------------------- |
| **CSV**  | Import into spreadsheets, BI tools, or custom analysis pipelines |
| **JSON** | Programmatic consumption, custom dashboard integration           |
| **API**  | Real-time data access for automated reporting workflows          |

### Compliance Exports

Every triage decision is persisted with a timestamp and LLM justification explaining why the finding was classified as a true positive, false positive, or won't-fix. Export this data as evidence for SOC 2, ISO 27001, or other compliance frameworks.

Compliance exports include:

- Finding ID and CWE category
- Triage classification with justification
- Fix outcome (PR merged, closed, pending)
- Timestamps for each state transition

For custom reporting, use the Pixee API to query triage and remediation data programmatically. See [API > Overview](/api/overview) for endpoints and authentication.

### Enterprise Observability

Self-hosted Pixee deployments include a bundled observability stack with metrics, logs, traces, and dashboards. Enterprise reporting data feeds into this stack, giving SRE teams visibility into both application-level metrics (triage volume, fix quality) and infrastructure-level metrics (analysis duration, queue depth).

For full observability configuration, see [Enterprise > Observability](/enterprise/observability).

## FAQ

### Does Pixee run on every commit?

By default, Pixee analyzes when new scanner findings are available, not on every commit. You can configure event-driven, scheduled, or on-demand analysis modes to match your workflow.

### Can I prevent Pixee from opening PRs during business hours?

Yes. Scheduled mode lets you set a cron expression that runs analysis during off-hours, so PRs are ready for review when your team starts work.

### How do I trigger a scan manually?

Use the Pixee dashboard or API to trigger on-demand analysis for any connected repository. Results and PRs appear as soon as analysis completes.

### Do I need to configure notifications to use Pixee?

No. Pixee uses your SCM platform's native notification system by default. PRs appear in your normal PR queue, and status checks integrate with your existing workflow. Additional channels (Slack, email, webhooks) are optional.

### Can I send notifications to different Slack channels for different repositories?

Yes. Notification routing supports per-repository and per-team channel assignments. Route backend repos to `#backend-security` and frontend repos to `#frontend-security`, for example.

### Does Pixee support PagerDuty or ServiceNow integration?

Pixee supports generic webhooks that integrate with PagerDuty, ServiceNow, Jira, or any system that accepts webhook payloads. Configure a webhook URL and select the event types you want forwarded.

### Can I export Pixee data for compliance audits?

Yes. Every triage decision and fix outcome is persisted with timestamps and justification. Export as CSV or JSON, or use the API for automated evidence collection. The data maps to common compliance frameworks including SOC 2 and ISO 27001.

### Does Pixee show fix merge rates?

Yes. Merge rate -- the percentage of Pixee PRs that developers review and merge -- is a primary metric tracked in the dashboard. See [Fix Safety](/how-it-works/fix-safety) for production metrics.

### Can I integrate Pixee reporting with Jira or ServiceNow?

Yes. Use the webhook and API integrations to push Pixee data to Jira, ServiceNow, or any system that accepts webhook payloads or REST API calls. See [API > Webhooks](/api/webhooks) for payload details.
