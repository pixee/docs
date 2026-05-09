---
title: Helm / BYO Kubernetes
slug: /enterprise/helm
track: leader
content_type: guide
seo_title: Helm / BYO Kubernetes - Deploy Pixee into EKS, GKE, AKS, or Self-Managed K8s
description: Deploy Pixee Enterprise via Helm chart into your existing Kubernetes cluster. Supports EKS, GKE, AKS, and self-managed K8s with BYO component options.
sidebar_position: 4
---

The Helm deployment installs Pixee into your existing Kubernetes cluster using a standard Helm chart. It supports EKS, GKE, AKS, and self-managed Kubernetes. Conditional subcharts let you swap embedded components for your own services -- BYO database (PostgreSQL 15+), object store (S3, Azure Blob, GCS), observability stack, and identity provider. This is the deployment model for organizations with established platform engineering teams.

## Who This Is For

The Helm deployment serves organizations that already run Kubernetes and want Pixee to fit into their existing infrastructure:

- **Platform engineering teams** comfortable with Helm-managed deployments and `values.yaml` configuration
- **Organizations with existing shared services** (databases, observability, identity providers) that prefer to use their own rather than embedded defaults
- **Multi-cloud enterprises** running EKS, GKE, AKS, or self-managed clusters

Compared to legacy on-premises AppSec products that ship as VM images, a native Helm chart fits modern platform-engineering workflows. Compared to cloud-only SaaS tools, it keeps code inside your VPC and IAM boundary.

## Prerequisites

| Requirement    | Specification                                   |
| -------------- | ----------------------------------------------- |
| **Kubernetes** | EKS, GKE, AKS, or self-managed (current stable) |
| **CPU**        | 8+ vCPU                                         |
| **RAM**        | 32+ GB                                          |
| **Storage**    | 100 GB+ SSD/NVMe                                |
| **Helm CLI**   | Current stable version                          |
| **Network**    | Port 443 (HTTPS)                                |

**Namespace isolation.** Pixee runs in a dedicated namespace. The Helm chart does not require cluster-admin privileges for day-to-day operation. Installation requires namespace creation and secret management permissions.

**Air-gapped variant.** If your Kubernetes cluster is in an air-gapped environment, see [Air-Gapped Deployment](/enterprise/air-gap) for additional configuration requirements including private LLM endpoints and container image pre-loading.

## Installation

The Helm deployment follows a standard pattern: add the chart repository, create a namespace with secrets, configure `values.yaml` for your environment (LLM provider, SCM integrations, authentication mode, and BYO component selections), and install. Preflight checks validate LLM provider connectivity and catch misconfiguration at install time. For current chart versions, values reference, and step-by-step instructions, see the [deployment guide](https://app.pixee.ai/docs/deploy).

## BYO Components

Conditional subcharts let you swap embedded defaults for your existing infrastructure. Disable any embedded component and provide your own.

| Component         | Embedded Default          | BYO Option                                       |
| ----------------- | ------------------------- | ------------------------------------------------ |
| **Object store**  | SeaweedFS                 | AWS S3, Azure Blob, GCS, any S3-compatible store |
| **Database**      | CloudNativePG             | External PostgreSQL 15+                          |
| **Observability** | VictoriaMetrics + Grafana | Customer's existing observability stack          |
| **Auth**          | Authentik OIDC            | Google Workspace, Microsoft Entra ID, Okta       |

### Credential Management for BYO Components

- **`existingSecret` support** -- All credential references support `existingSecret` for integration with external secret managers (Vault, External Secrets Operator, SOPS). No credentials need to be stored in Helm values.
- **Pod identity support** -- IRSA (AWS), Workload Identity (GCP), and Managed Identity (Azure) are supported for object store access, alongside static key configuration.
- **BYO database secrets** -- External PostgreSQL connection details can be provided as Kubernetes secrets with `existingSecret` references.

Pod identity support (IRSA, Workload Identity, Managed Identity) eliminates static credentials for cloud-native deployments -- a strong signal for organizations that have adopted zero-trust infrastructure.

## Cloud Provider Storage Classes

Platform engineers: verify your storage class matches your cloud provider.

| Cloud Provider  | Storage Class  |
| --------------- | -------------- |
| **EKS**         | `gp2` / `gp3`  |
| **GKE**         | `standard-rwo` |
| **AKS**         | `managed-csi`  |
| **K3s / local** | default        |

## Multi-SCM Configuration

A single Helm deployment supports all four SCM platforms simultaneously. Configure each platform independently:

| SCM Platform     | Auth Method                                         | Self-Hosted Support                      |
| ---------------- | --------------------------------------------------- | ---------------------------------------- |
| **GitHub**       | GitHub App (private key + webhook secret)           | GitHub Enterprise Server (custom domain) |
| **GitLab**       | Personal access token (service account recommended) | GitLab self-hosted (custom base URI)     |
| **Azure DevOps** | PAT with webhook user/password                      | Azure DevOps Server                      |
| **Bitbucket**    | API tokens                                          | Bitbucket Cloud and Server               |

Enterprise controls include `member_projects_only` toggles (GitLab) to restrict Pixee to projects where the service account is an explicit member, and optional work-item linking (Azure DevOps) for organizations requiring linked work items on pull requests.

For organizations with multiple SCM platforms -- for example, GitLab on-premises for core development and GitHub for open-source contributions -- a single Pixee deployment covers both with the same triage and remediation engine.

## Upgrading

Pixee releases updates approximately every two weeks. Standard Helm upgrade workflow applies:

1. Review release notes for the new version
2. Run `helm upgrade` with your existing values file
3. Verify pods restart and the UI is accessible

Approximately 25 releases have shipped in the last 6 months. The platform is actively maintained and improved on a rapid cadence. Review release notes before each upgrade to identify any breaking changes or new configuration options.

Before upgrading, back up your current `values.yaml` file. If an upgrade introduces an issue, roll back to the previous Helm release using standard Helm rollback commands.
