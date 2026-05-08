---
title: Embedded Cluster
slug: /enterprise/embedded-cluster
track: leader
content_type: guide
seo_title: Embedded Cluster - Deploy Pixee on a Single VM Without Kubernetes Expertise
description: Deploy Pixee Enterprise as a turnkey appliance on a single Linux VM. K3s-based with KOTS admin console. No Kubernetes expertise required.
sidebar_position: 3
---

The embedded cluster deployment installs the full Pixee platform -- Kubernetes runtime, storage, authentication, and observability -- as a turnkey single-tenant appliance on a single Linux VM. No Kubernetes expertise is needed. A single command installs K3s, the Pixee platform, and a form-based admin console for day-two operations. This is the fastest path to self-hosted Pixee for organizations without existing Kubernetes infrastructure.

## Who This Is For

The embedded cluster is built for organizations that need self-hosted deployment but do not have (or do not want to use) existing Kubernetes infrastructure:

- **Regulated industries** (finance, healthcare, public sector) requiring dedicated-tenant deployment inside the customer perimeter
- **Teams without Kubernetes engineers** that still need self-hosted security automation
- **Evaluation environments** where standing up a full Kubernetes cluster is not justified for a proof of concept

Most AI-assisted AppSec tools are cloud-only SaaS. The embedded cluster delivers the same triage and remediation engine as the cloud offering, running entirely within your network, without requiring platform engineering expertise.

## Prerequisites

Verify these requirements with your infrastructure team before installation.

| Requirement          | Specification                                               |
| -------------------- | ----------------------------------------------------------- |
| **Operating system** | Ubuntu 24.04+ (recommended), RHEL 9, Rocky Linux, AlmaLinux |
| **CPU**              | 8 vCPU minimum                                              |
| **RAM**              | 32 GB minimum                                               |
| **Storage**          | 100 GB+ SSD/NVMe, under 10 ms write latency                 |
| **Network**          | Port 443 (HTTPS), Port 30000 (admin console)                |
| **Internet**         | Required for initial install; proxy support available       |

The VM can run on any infrastructure: physical servers, VMware, Hyper-V, cloud VMs (EC2, Azure VMs, GCE), or any other virtualization platform.

**Storage performance matters.** The 10 ms write latency requirement is not optional. Pixee persists triage decisions, fix metadata, and analysis state to disk. Slow storage causes analysis timeouts and degraded platform performance. Use SSD or NVMe -- not spinning disk or network-attached storage with high latency.

**Proxy environments.** If your VM accesses the internet through a proxy, proxy configuration is supported during installation. TLS-intercepting proxies are also supported via CA cert injection.

## Installation

The embedded cluster installs with a single command on a Linux VM meeting the prerequisites above. The installer provisions K3s (Kubernetes 1.32), deploys the Pixee platform, and starts a KOTS-powered admin console on port 30000. The admin console provides a form-based UI for all configuration -- domain, TLS, authentication, LLM provider, and SCM connections. No YAML editing or manual Kubernetes configuration is required at any point. For the current installer command and step-by-step walkthrough, see the [deployment guide](https://app.pixee.ai/docs/deploy).

**Configuration options available in the admin console:**

| Configuration        | Options                                                                      |
| -------------------- | ---------------------------------------------------------------------------- |
| **Domain and TLS**   | Upload certificate, self-signed certificate, or Let's Encrypt                |
| **Authentication**   | None (evaluation), embedded OIDC, Google Workspace, Microsoft Entra ID, Okta |
| **LLM provider**     | OpenAI, Azure AI Foundry, Anthropic, Azure Anthropic                         |
| **SCM integrations** | GitHub App, GitLab PAT, Azure DevOps PAT, Bitbucket API token                |

Each provider selection includes preflight checks that catch misconfiguration at install time -- not when you run your first analysis.

## Admin Console Overview

The KOTS admin console is the day-two operations interface for the embedded cluster:

- **Configuration management** -- All settings are managed through a form-based UI. Changes are applied without manual Kubernetes intervention.
- **Upgrades** -- New Pixee versions are delivered through the admin console. Upgrades are single-step operations with rollback support.
- **Health monitoring** -- Platform status, service health, and resource usage are visible from the console dashboard.
- **Diagnostics** -- Support bundle generation collects logs and configuration data for troubleshooting. Log size and age limits are configurable before generation.
- **Backup and restore** -- Data protection operations are managed from the admin console.

The key message for infrastructure teams: you do not need to learn Kubernetes to operate Pixee. The admin console abstracts all cluster management into a familiar web interface.

## Upgrading

Pixee releases updates approximately every two weeks. Upgrades are delivered through the admin console:

1. The admin console notifies you when a new version is available
2. Review the release notes in the console
3. Apply the upgrade as a single-step operation
4. The console displays upgrade progress and rolls back automatically if the upgrade fails

The embedded cluster version tracks the Pixee Enterprise release cadence. Approximately 25 releases have shipped in the last 6 months -- the platform is actively maintained and improved.

## Security Considerations

The embedded cluster runs as a single-tenant deployment on your infrastructure:

- **Data isolation.** All source code, scanner findings, and triage decisions stay on the VM. Only LLM inference and license validation generate outbound traffic.
- **Network control.** The VM requires port 443 (HTTPS for SCM webhooks and UI access) and port 30000 (admin console). No other inbound ports are needed.
- **Credential management.** SCM tokens and LLM API keys are stored in Kubernetes secrets within the cluster. External secret manager integration is supported.
- **TLS options.** Upload your own certificate, use a self-signed certificate for evaluation, or configure Let's Encrypt for automatic certificate management.

For the full security review, see [Security Architecture](/enterprise/security-architecture).

## When to Choose Helm Instead

The embedded cluster is the right choice for most organizations without existing Kubernetes. Consider the [Helm / BYO Kubernetes](/enterprise/helm) deployment if:

- You already have an EKS, GKE, AKS, or self-managed Kubernetes cluster
- You want to swap embedded components for your own services (BYO database, BYO object store, BYO observability)
- Your platform engineering team prefers Helm-managed deployments and wants to integrate Pixee into existing cluster operations

Both deployment models deliver the same triage and remediation capabilities. The choice is about infrastructure preference, not product functionality.

## Frequently Asked Questions

### Do I need Kubernetes experience to deploy Pixee?

No. The embedded cluster deployment handles all Kubernetes components automatically. The admin console is a form-based UI for all configuration -- no YAML editing, no kubectl commands, no cluster management.

### What Kubernetes distribution does the embedded cluster use?

The embedded cluster is built on K3s (Kubernetes 1.32) distributed via Replicated Embedded Cluster.

### Can I run the embedded cluster in a VM on my existing infrastructure?

Yes. The embedded cluster runs on any Linux VM that meets the prerequisites -- physical servers, VMware, Hyper-V, cloud VMs (EC2, Azure VMs, GCE), or any other virtualization platform.

### How do I upgrade the embedded cluster?

Upgrades are managed through the KOTS admin console. New versions are delivered as single-step upgrades with rollback support. No manual Kubernetes operations are required.
