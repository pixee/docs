---
title: Observability
slug: /enterprise/observability
track: leader
content_type: guide
seo_title: Observability - Metrics, Logs, Traces, and Dashboards for Pixee Enterprise
description: Monitor Pixee Enterprise with bundled VictoriaMetrics, Grafana dashboards, distributed tracing, and log aggregation. BYO observability supported.
sidebar_position: 9
---

Pixee Enterprise ships a complete observability stack -- metrics, logs, traces, and dashboards -- bundled in the Helm chart. No separate purchase or manual setup required. SRE teams can use the bundled stack as-is, disable individual components, or route telemetry to their existing observability platform. This page covers what is included, how to integrate with your existing stack, and key metrics to monitor.

## Bundled Observability Stack

The Helm chart includes five observability components, each shipped as a conditional subchart that can be independently enabled or disabled:

| Component                     | Purpose                        | Replaceable?                             |
| ----------------------------- | ------------------------------ | ---------------------------------------- |
| **VictoriaMetrics**           | Metrics collection and storage | Yes -- BYO Prometheus or VictoriaMetrics |
| **Victoria-logs + collector** | Log aggregation                | Yes -- BYO log pipeline                  |
| **Victoria-traces**           | Distributed tracing            | Yes -- BYO tracing solution              |
| **Grafana k8s-monitoring**    | Dashboards and visualization   | Yes -- BYO Grafana                       |
| **Sentry**                    | Error reporting                | Toggleable (opt-in / opt-out)            |

Pixee ships curated dashboards built specifically for the Pixee platform -- not just upstream chart defaults. These dashboards cover platform health, analysis throughput, LLM performance, and fix quality metrics.

**Why this matters for enterprise evaluation:** Legacy on-premises scanners (Checkmarx, Veracode) predate Kubernetes-native observability and do not ship monitoring. SaaS scanners do not expose observability because the customer does not run the infrastructure. Pixee ships both the platform and the tools to monitor it.

## Integrating with Your Existing Stack

Most enterprise platform teams already run an observability stack. Pixee integrates rather than duplicating.

**Disable embedded subcharts.** Turn off any embedded component (VictoriaMetrics, Victoria-logs, Victoria-traces, Grafana) and configure Pixee to emit telemetry to your existing platform. Each subchart is independently toggleable.

**Grafana Cloud integration.** Grafana Cloud Private Data Connector support routes metrics from your self-hosted Pixee deployment to your Grafana Cloud tenant without exposing the cluster to inbound connections.

**Standard pipelines.** Pixee's telemetry is compatible with standard Prometheus and OpenTelemetry pipelines. If your team already runs Prometheus, Datadog, or a similar platform, Pixee's metrics integrate without custom adapters.

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

## Frequently Asked Questions

### Does Pixee include monitoring out of the box?

Yes. The Helm chart bundles VictoriaMetrics (metrics), Victoria-logs (logs), Victoria-traces (distributed tracing), and Grafana dashboards. No separate purchase or manual installation required.

### Can I route Pixee telemetry to my existing Grafana or Prometheus?

Yes. Disable the embedded observability subcharts and configure Pixee to emit metrics to your existing stack. Grafana Cloud Private Data Connector integration is also supported.

### What dashboards does Pixee provide?

Pixee includes curated Grafana dashboards for platform health, analysis throughput, LLM performance, and fix quality metrics. These are Pixee-specific dashboards, not just upstream chart defaults.
