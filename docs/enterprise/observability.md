---
title: Observability
slug: /enterprise/observability
track: leader
content_type: guide
seo_title: Observability - Metrics, Logs, Traces, and Dashboards for Pixee Enterprise
description: Monitor Pixee Enterprise with a bundled VictoriaMetrics, VictoriaLogs, and VictoriaTraces stack, with dashboards served through VMUI. BYO observability supported.
sidebar_position: 9
---

Pixee Enterprise ships a complete observability stack -- metrics, logs, traces, and dashboards -- bundled in the Helm chart. No separate purchase or manual setup required. SRE teams can use the bundled stack as-is, disable individual components, or route telemetry to their existing observability platform. This page covers what is included, how to integrate with your existing stack, and key metrics to monitor.

## Bundled Observability Stack

The Helm chart includes four observability components, each shipped as a conditional subchart that can be independently enabled or disabled:

| Component                     | Purpose                                     | Replaceable?                             |
| ----------------------------- | ------------------------------------------- | ---------------------------------------- |
| **VictoriaMetrics (VMUI)**    | Metrics collection, storage, and dashboards | Yes -- BYO Prometheus or VictoriaMetrics |
| **VictoriaLogs + collector**  | Log aggregation                             | Yes -- BYO log pipeline                  |
| **VictoriaTraces**            | Distributed tracing                         | Yes -- BYO tracing solution              |
| **Sentry**                    | Error reporting                             | Toggleable (opt-in / opt-out)            |

Pixee ships curated dashboards built specifically for the Pixee platform, served through the VictoriaMetrics VMUI at `/metrics/vmui/#/dashboards` once local metrics are enabled. These dashboards cover AI service performance, per-finding task metrics, analysis throughput, LLM performance, and fix quality.

**Why this matters for enterprise evaluation:** Legacy on-premises scanners (Checkmarx, Veracode) predate Kubernetes-native observability and do not ship monitoring. SaaS scanners do not expose observability because the customer does not run the infrastructure. Pixee ships both the platform and the tools to monitor it.

## Integrating with Your Existing Stack

Most enterprise platform teams already run an observability stack. Pixee integrates rather than duplicating.

**Disable embedded subcharts.** Turn off any embedded component (VictoriaMetrics, VictoriaLogs, VictoriaTraces) and configure Pixee to emit telemetry to your existing platform. Each subchart is independently toggleable.

**Standard pipelines.** VictoriaMetrics and VictoriaLogs are compatible with standard Prometheus and OpenTelemetry pipelines, so you can scrape, remote-write, or forward Pixee telemetry to an external platform (Prometheus, Grafana, Datadog, or similar) without custom adapters or exposing the cluster to inbound connections.

**Verification.** After configuring your integration, verify that metrics, logs, and traces are flowing to your platform. Pixee's admin console shows telemetry status for embedded components.

## Key Metrics to Monitor

For day-two operations teams, these are the metrics that indicate platform health and business value:

| Metric Category         | What to Watch                                         | Why It Matters                                                     |
| ----------------------- | ----------------------------------------------------- | ------------------------------------------------------------------ |
| **Analysis throughput** | Tasks completed per hour, queue depth                 | Platform is processing findings at expected rate                   |
| **LLM latency**         | Inference response time per tier                      | Performance tuning; identifies slow or rate-limited providers      |
| **Fix quality**         | Average safety, effectiveness, and cleanliness scores | Quality monitoring; trends indicate model or configuration changes |
| **Merge rate**          | Percentage of PRs merged by developers                | Adoption tracking; the primary business-value metric               |
| **Error rate**          | Failed analyses, retries, suppressed fixes            | Operational health; spikes indicate configuration or LLM issues    |

**Business metrics vs. platform metrics:** Merge rate, triage volume, and remediation velocity are business metrics visible in Pixee's reporting dashboard. Analysis throughput, LLM latency, and error rates are platform metrics visible in the observability stack. Both matter for different audiences -- share business metrics with security leadership and platform metrics with SRE.

For business-level reporting (merge rate trends, triage reduction, MTTR), see [Enterprise Overview > Measuring Success](/enterprise/overview#measuring-success).

## Operational Controls

Operational settings are configurable through the KOTS admin console (embedded cluster) or Helm values (BYO Kubernetes):

| Control                          | Description                                              |
| -------------------------------- | -------------------------------------------------------- |
| **Sentry toggle**                | Enable or disable error reporting                        |
| **Custom metrics toggle**        | Enable or disable custom Pixee metrics                   |
| **LLM debug mode**               | Verbose logging for LLM request/response troubleshooting |
| **Support bundle configuration** | Log size and age limits for diagnostic bundle generation |

For troubleshooting operational issues, see [Enterprise Troubleshooting](/enterprise/troubleshooting).
