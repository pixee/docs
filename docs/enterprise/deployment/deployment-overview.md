---
title: Deployment Options
slug: /enterprise/deployment
track: leader
content_type: guide
seo_title: Deployment Options - SaaS, Self-Hosted, and Air-Gapped Security Automation
description: "Compare Pixee deployment models: cloud SaaS, embedded cluster, Helm/BYO Kubernetes, and air-gapped. Includes data flow tables and infrastructure requirements."
sidebar_position: 1
---

Pixee offers four deployment models: cloud SaaS, a turnkey embedded cluster for organizations without Kubernetes, a standard Helm chart for existing EKS/GKE/AKS clusters, and a fully air-gapped deployment with private LLM endpoints. Every model delivers the same triage and remediation engine. The only difference is where the infrastructure runs and how data flows through your network.

This page provides architecture descriptions, data flow tables, and infrastructure requirements for each model. Security teams reviewing Pixee for enterprise deployment should start here.

## Deployment Model Comparison

### Cloud SaaS Architecture

Pixee manages all infrastructure. The customer installs a GitHub App, GitLab PAT, Azure DevOps PAT, or Bitbucket API token. Source code access flows through the SCM integration. Analysis, triage, and LLM inference run on Pixee-managed infrastructure. Fixes are delivered as pull requests back to the customer's SCM.

**Component layout:** Pixee platform (Pixee-managed cloud) connects to customer SCM via API. LLM inference runs on Pixee-managed providers. All processing happens outside the customer network. Results return as PRs through the SCM API.

### Embedded Cluster Architecture

A single Linux VM hosts the complete Pixee platform as a turnkey appliance. The installer provisions K3s (current stable Kubernetes), storage, authentication, and observability automatically. The KOTS admin console provides a form-based UI for configuration. No Kubernetes expertise is required.

**Component layout:** Customer VM runs Pixee platform, analysis service, and user platform. LLM inference routes to the customer's chosen provider (OpenAI, Azure AI Foundry, Anthropic, or Azure Anthropic) from within the customer network. SCM integration connects to internal or cloud-hosted SCM. Admin console runs on port 30000.

### Helm / BYO Kubernetes Architecture

The Pixee Helm chart deploys into an existing customer-managed Kubernetes cluster. Conditional subcharts let platform engineering teams swap embedded components for their own services -- BYO database, object store, observability, and identity provider.

**Component layout:** Customer Kubernetes cluster (EKS, GKE, AKS, or self-managed) runs Pixee platform, analysis service, and user platform as pods. Embedded subcharts (SeaweedFS, CloudNativePG, VictoriaMetrics, Grafana, Authentik) are each independently replaceable. LLM inference routes to the customer's provider. SCM integration connects via the cluster's network.

### Air-Gapped Architecture

The same Helm chart deploys into a disconnected environment. LLM inference runs against a customer-hosted private endpoint. Source code and findings never traverse the public internet.

**Component layout:** Customer Kubernetes cluster in an isolated network runs the full Pixee stack. LLM inference routes to a private endpoint (Azure AI Foundry, Azure Anthropic, or OpenAI-compatible gateway) within the customer's network boundary. The only outbound connection is license validation, which can be proxied. SCM integration connects to the internal SCM instance.

| Model                | Infrastructure | LLM             | Data Residency     | K8s Required     | Best For                          |
| -------------------- | -------------- | --------------- | ------------------ | ---------------- | --------------------------------- |
| **Cloud SaaS**       | Pixee-managed  | Pixee-managed   | Pixee cloud        | No               | Zero-infra teams                  |
| **Embedded Cluster** | Customer VM    | Customer-chosen | Customer network   | No (K3s bundled) | No-K8s orgs, regulated industries |
| **Helm / BYO K8s**   | Customer K8s   | Customer-chosen | Customer network   | Yes              | Platform-engineering teams        |
| **Air-Gapped**       | Customer K8s   | Customer-hosted | Air-gapped network | Yes              | Federal, finance, healthcare      |

## Data Flow by Deployment Model

This table answers the question security teams ask first: "What data leaves my network?"

| Data Type                | Cloud SaaS          | Embedded Cluster          | Helm / BYO K8s            | Air-Gapped                   |
| ------------------------ | ------------------- | ------------------------- | ------------------------- | ---------------------------- |
| Source code snippets     | Sent to Pixee cloud | Stays in customer network | Stays in customer network | Stays in customer network    |
| Scanner findings (SARIF) | Sent to Pixee cloud | Stays in customer network | Stays in customer network | Stays in customer network    |
| LLM inference requests   | Pixee-managed       | Customer's LLM provider   | Customer's LLM provider   | Customer's private endpoint  |
| PR/MR content            | Via SCM API         | Via SCM API (internal)    | Via SCM API (internal)    | Via SCM API (internal)       |
| License validation       | Pixee cloud         | Pixee cloud (or proxy)    | Pixee cloud (or proxy)    | Pixee cloud (proxy required) |
| Telemetry (opt-in)       | Pixee cloud         | Pixee cloud (toggleable)  | Pixee cloud (toggleable)  | Blocked                      |

**Key takeaway for self-hosted models:** Source code, scanner findings, and LLM requests stay in your network. The only outbound connection is license validation, which supports proxy configuration.

## Infrastructure Requirements

| Requirement          | Embedded Cluster                                            | Helm / BYO K8s                                        |
| -------------------- | ----------------------------------------------------------- | ----------------------------------------------------- |
| **Compute**          | 8 vCPU, 32 GB RAM                                           | 8+ vCPU, 32+ GB RAM                                   |
| **Storage**          | 100 GB+ SSD/NVMe (under 10 ms write latency)                | 100 GB+ SSD/NVMe                                      |
| **Operating system** | Ubuntu 24.04+ (recommended), RHEL 9, Rocky Linux, AlmaLinux | N/A (Kubernetes cluster)                              |
| **Kubernetes**       | K3s bundled (current stable)                                | EKS, GKE, AKS, or self-managed                        |
| **Helm CLI**         | N/A                                                         | Current stable version                                |
| **Network**          | Port 443 (HTTPS), Port 30000 (admin console)                | Port 443 (HTTPS)                                      |
| **Internet**         | Required for initial install; proxy support available       | Required for initial install; proxy support available |

## Multi-Tenancy and Business Unit Isolation

A single Pixee deployment supports multiple SCM organizations simultaneously. Repository-level access controls restrict which users can view and act on which repositories, providing organizational boundaries within a shared deployment.

**Role-based access control.** Three roles -- Admin, Security Lead, and Member -- provide access granularity within a deployment. Admins manage configuration and user access. Security Leads oversee triage decisions and fix policies. Members interact with PRs in their assigned repositories.

**Regulatory data isolation.** For business units with strict data separation requirements -- such as investment banking and consumer banking divisions, or units subject to different regulatory regimes -- separate Pixee deployments are recommended. Separate deployments ensure that code, findings, triage decisions, and LLM inference requests from one business unit never share infrastructure with another.

Contact Pixee solutions engineering for guidance on multi-deployment architectures for regulated environments.

## Network Connections by Deployment Model

For security teams conducting network reviews, this table maps every external connection Pixee requires.

| Connection                    | Purpose                       | Cloud SaaS    | Embedded Cluster    | Helm / BYO K8s      | Air-Gapped       |
| ----------------------------- | ----------------------------- | ------------- | ------------------- | ------------------- | ---------------- |
| SCM webhooks (inbound 443)    | Repository events             | Pixee cloud   | Customer network    | Customer network    | Customer network |
| LLM endpoint (outbound)       | AI inference                  | Pixee-managed | Customer's provider | Customer's provider | Private endpoint |
| License server (outbound)     | License validation            | Pixee cloud   | Direct or proxy     | Direct or proxy     | Proxy required   |
| Telemetry (outbound, opt-in)  | Usage metrics                 | Pixee cloud   | Toggleable          | Toggleable          | Blocked          |
| Container registry (outbound) | Image pulls (install/upgrade) | N/A           | Required            | Required            | Pre-loaded       |

No other outbound connections are required. Self-hosted deployments require no inbound connections except SCM webhooks on port 443.

## Choosing a Deployment Model

Use this decision tree to narrow down your model:

1. **Can you manage Kubernetes?**
   - Yes -- [Helm / BYO Kubernetes](/enterprise/helm)
   - No -- [Embedded Cluster](/enterprise/embedded-cluster)

2. **Do you require air-gapped deployment?**
   - Yes -- [Air-Gapped Deployment](/enterprise/air-gap)
   - No -- continue

3. **Do you want zero infrastructure management?**
   - Yes -- Cloud SaaS
   - No -- embedded cluster or Helm (based on step 1)

4. **Do you have regulatory data residency requirements?**
   - Banking or healthcare with strict data residency -- embedded cluster or air-gapped
   - Federal or classified environments -- air-gapped
   - Standard enterprise -- any self-hosted model based on your Kubernetes posture

## Security Review Summary

**Data classification:** Pixee analyzes vulnerability-relevant code snippets -- not entire repositories. No absolute paths, repository URLs, git metadata, commit hashes, or author information are sent to LLM inference. Scanner findings (SARIF data) stay within the deployment boundary for all self-hosted models.

**Network requirements:** Self-hosted deployments require outbound access for license validation only (proxyable). LLM inference routes to the customer's chosen provider within the customer's network. No inbound connections are required except SCM webhooks on port 443.

**Credential management:** SCM tokens (GitHub App private key, GitLab PAT, Azure DevOps PAT, Bitbucket API token) and LLM API keys are stored in Kubernetes secrets. External secret manager integration (Vault, External Secrets Operator, SOPS) is supported via `existingSecret` references. No credentials are stored in Helm values.

**For the full security review:** See [Security Architecture](/enterprise/security-architecture) for data flow diagrams, access control details, AI governance controls, and credential handling specifics.

## Sizing Guidance

| Deployment Size | Repositories | Recommended Resources              | Deployment Model            |
| --------------- | ------------ | ---------------------------------- | --------------------------- |
| Small           | Up to 50     | 8 vCPU, 32 GB RAM, 100 GB SSD      | Embedded Cluster            |
| Medium          | 50-500       | 16 vCPU, 64 GB RAM, 250 GB SSD     | Helm / BYO K8s              |
| Large           | 500+         | 32+ vCPU, 128+ GB RAM, 500+ GB SSD | Helm / BYO K8s (multi-node) |

These are starting recommendations. Actual resource requirements depend on finding volume, concurrent analysis workload, and LLM inference latency. Contact Pixee solutions engineering for sizing guidance on large deployments.

