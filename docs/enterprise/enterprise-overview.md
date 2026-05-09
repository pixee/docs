---
title: Enterprise Overview
slug: /enterprise/overview
track: leader
content_type: conceptual
seo_title: Enterprise Overview - Self-Hosted Security Automation
description: Pixee Enterprise deployment models, compliance controls, identity management, and operational metrics.
sidebar_position: 1
---

Pixee Enterprise deploys into your infrastructure -- cloud SaaS, turnkey embedded cluster, Helm into existing Kubernetes, or fully air-gapped with your own LLM. Every deployment model delivers the same triage and remediation engine, the same scanner integrations, and the same audit trail. This section covers deployment options, compliance, security architecture, and how to measure operational impact.

## Enterprise Capabilities

Enterprise adds infrastructure control, identity management, and compliance capabilities on top of the core triage and remediation engine.

- **Self-hosted deployment** -- run Pixee on your infrastructure with your network policies
- **SSO and access control** -- Google Workspace, Microsoft Entra ID, Okta, or embedded OIDC
- **Bring Your Own Model (BYOM)** -- choose your LLM provider, own the keys, control the bill
- **Compliance controls** -- audit-ready triage records, exportable evidence, framework alignment
- **Bundled observability** -- metrics, logs, traces, and dashboards ship in the Helm chart
- **Enterprise support** -- dedicated solutions engineering

Pixee ships approximately 25 releases every 6 months. Four deployment models, four LLM provider families, and four SCM integrations (GitHub, GitLab, Azure DevOps, Bitbucket) are available from a single deployment.

A single Pixee Enterprise deployment supports multiple SCM platforms simultaneously.

## Deployment Models at a Glance

| Model                     | Best For                                              | Infra Required                             | Time to Deploy |
| ------------------------- | ----------------------------------------------------- | ------------------------------------------ | -------------- |
| **Cloud SaaS**            | Teams wanting zero infrastructure management          | None                                       | Minutes        |
| **Embedded Cluster**      | Orgs without Kubernetes, regulated industries         | Single Linux VM (8 vCPU, 32 GB RAM)        | Under 1 hour   |
| **Helm / BYO Kubernetes** | Orgs with existing EKS/GKE/AKS clusters               | Customer Kubernetes cluster                | Under 1 hour   |
| **Air-Gapped**            | Federal, financial services, healthcare (no internet) | Customer Kubernetes + private LLM endpoint | Hours          |

Every model delivers the same triage and remediation engine. The only difference is where the infrastructure runs and how data flows through your network. See [Deployment Options](/enterprise/deployment) for architecture diagrams, data flow tables, and infrastructure requirements.

## Enterprise Capabilities Summary

| Capability                                                                  | Status | Detail Page                                                |
| --------------------------------------------------------------------------- | ------ | ---------------------------------------------------------- |
| Self-hosted deployment (embedded cluster and Helm)                          | GA     | [Deployment Options](/enterprise/deployment)               |
| Air-gapped deployment with private LLM                                      | GA     | [Air-Gapped Deployment](/enterprise/air-gap)               |
| SSO (Google Workspace, Microsoft Entra ID, Okta)                            | GA     | [Security Architecture](/enterprise/security-architecture) |
| Bring Your Own Model (OpenAI, Azure AI Foundry, Anthropic)                  | GA     | [Bring Your Own Model](/enterprise/byom)                   |
| Bundled observability (metrics, logs, traces, dashboards)                   | GA     | [Observability](/enterprise/observability)                 |
| Compliance mapping (SOC 2, HIPAA, FedRAMP, PCI-DSS, NIST 800-53, ISO 27001) | GA     | [Compliance](/enterprise/compliance)                       |
| Multi-SCM support (GitHub, GitLab, Azure DevOps, Bitbucket)                 | GA     | [Getting Started](/)                                       |
| Hierarchical LLM routing (7 named tiers)                                    | GA     | [Bring Your Own Model](/enterprise/byom)                   |
| Audit-ready triage records with LLM justification                           | GA     | [Compliance](/enterprise/compliance)                       |
| Role-based access control                                                   | GA     | [Security Architecture](/enterprise/security-architecture) |

## Measuring Success

Track these metrics from the Pixee reporting dashboard to evaluate operational impact:

| Metric                          | What It Measures                                                  | Source                                |
| ------------------------------- | ----------------------------------------------------------------- | ------------------------------------- |
| **Merge rate**                  | Percentage of Pixee PRs merged by developers                      | Pixee dashboard: fix activity         |
| **Triage reduction**            | Percentage of findings automatically classified (TP/FP/won't-fix) | Pixee dashboard: triage summary       |
| **MTTR**                        | Time from finding detection to merged fix                         | Pixee reporting: remediation velocity |
| **Compliance window adherence** | Critical/high findings remediated within required timeframes      | Pixee reporting + compliance tool     |
| **Finding volume trend**        | Total open findings over time                                     | Pixee dashboard: backlog view         |

See [Security & Trust](/platform/security) for production metrics on fix quality and validation.

## What's Next

**Evaluating deployment options?** Start with [Deployment Options](/enterprise/deployment) for architecture diagrams and data flow tables.

**Planning the rollout?** The [Phased Rollout Guide](/enterprise/phased-rollout) covers the single-repo-to-enterprise adoption path with decision gates at each phase.

**Reviewing compliance requirements?** The [Compliance](/enterprise/compliance) page maps Pixee capabilities to SOC 2, HIPAA, FedRAMP, PCI-DSS, NIST 800-53, and ISO 27001.
