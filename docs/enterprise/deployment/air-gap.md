---
title: Air-Gapped Deployment
slug: /enterprise/air-gap
track: leader
content_type: guide
seo_title: Air-Gapped Deployment - Run Pixee Without Internet Access
description: Deploy Pixee in air-gapped environments with private LLM endpoints. Covers capabilities, requirements, and known limitations for disconnected deployments.
sidebar_position: 5
---

Pixee supports air-gapped deployment for regulated and classified environments that cannot call public AI APIs. Source code and findings never leave your network. LLM inference runs against a customer-hosted private endpoint (Azure AI Foundry, Azure Anthropic, or any OpenAI-compatible gateway). This page covers what works, what is required, and what limitations exist in disconnected environments.

## What "Air-Gapped" Means for Pixee

In Pixee's air-gapped deployment:

- **Source code** never traverses the public internet
- **Scanner findings** stay within your network
- **LLM requests** route to a customer-hosted private endpoint
- **Fixes** are delivered as PRs to your internal SCM

The same Pixee platform, the same Helm chart, and the same upgrade path apply as in connected deployments. Air-gapped mode changes where LLM inference runs and how network traffic flows -- not what the product does.

:::warning[Not fully zero-internet]
"Air-gapped" in this context means LLM inference is private and code stays internal. License validation still requires a network path to Pixee servers — either direct or through a proxy. If your policy prohibits all outbound connections without exception, read [Known Limitations](#known-limitations) below and contact Pixee solutions engineering before proceeding.
:::

## Supported Private LLM Endpoints

| Provider                          | Description                                         | Notes                                                      |
| --------------------------------- | --------------------------------------------------- | ---------------------------------------------------------- |
| **Azure AI Foundry**              | Azure-hosted models in customer's Azure tenant      | Customer-owned keys, runs in customer's Azure subscription |
| **Azure Anthropic**               | Anthropic models via Azure marketplace              | Customer-owned keys, Azure-hosted                          |
| **OpenAI-compatible gateway**     | Self-hosted endpoint exposing OpenAI-compatible API | Custom header auth supported for enterprise gateways       |
| **Anthropic via private network** | Direct Anthropic API over private path              | Requires network path to Anthropic from within the cluster |

All providers support custom endpoint URLs and custom header name/value pairs for enterprise gateway authentication. Per-provider preflight checks validate LLM connectivity at install time, catching misconfiguration before your first analysis runs.

## Requirements

| Requirement            | Specification                                                           |
| ---------------------- | ----------------------------------------------------------------------- |
| **Kubernetes**         | Same as Helm deployment -- EKS, GKE, AKS, or self-managed               |
| **LLM endpoint**       | Customer-hosted, accessible from the Pixee namespace within the cluster |
| **Network**            | Proxy support (`httpProxy`, `httpsProxy`, `noProxy`)                    |
| **TLS**                | CA cert injection for TLS-intercepting proxies                          |
| **License validation** | Outbound path to Pixee license server (direct or proxied)               |

Infrastructure requirements (CPU, RAM, storage) match the [Helm / BYO Kubernetes](/enterprise/helm) deployment.

## Known Limitations

This section is direct about what air-gapped deployment does not support. Discovering a limitation during a proof of concept that was not disclosed in documentation wastes everyone's time.

**License validation requires a network path.** Pixee cannot operate in a truly zero-internet-connectivity environment. License validation must reach Pixee servers, either directly or through a proxy. If your security policy prohibits all outbound connections, contact Pixee solutions engineering before proceeding. There is no offline license mode.

**LLM quality depends on the private endpoint.** The quality of triage decisions and remediation fixes depends on the LLM model available at the private endpoint. If the private model is equivalent to production defaults, triage and fix quality will be identical. Models with lower capability may produce lower merge rates and less accurate triage classifications.

**Model updates require manual intervention.** In connected deployments, Pixee can leverage updated model configurations automatically. In air-gapped environments, model upgrades require manual endpoint configuration changes and testing.

**Web search and external research features are unavailable.** LLM tiers that depend on internet access (web search, deep research) do not function in air-gapped deployments. Triage and remediation that rely on code analysis continue to work. The affected capabilities are research-augmented features, not core triage and remediation.

**Initial deployment takes longer.** Expect additional time for image loading into the local container registry, private endpoint configuration, network verification, and proxy setup compared to connected deployments.

**Deterministic codemods are unaffected.** Deterministic codemods that require no LLM involvement function identically in air-gapped environments. These fixes carry zero dependency on any LLM endpoint.

## Proxy and TLS Configuration

Air-gapped environments frequently involve proxy servers and TLS-intercepting proxies. Pixee supports both.

**Proxy configuration:** Set `httpProxy`, `httpsProxy`, and `noProxy` in Helm values. Per-provider endpoint overrides are available if different LLM providers require different proxy paths.

**TLS-intercepting proxy support:** If your network uses a TLS-intercepting proxy, inject your CA certificate so Pixee can establish trust with internal endpoints. This is configured during installation.

**Verification:** After configuration, validate that the Pixee platform can reach the LLM endpoint and the license server through the proxy. Preflight checks cover LLM connectivity. License validation can be verified from the admin console.

## Industry Context

Air-gapped deployments serve specific regulatory environments:

- **Federal and defense** -- Classified environments where source code cannot traverse public networks. Government customer approval processes require documented data flow before deployment.
- **Financial services** -- Banking regulators require strict data controls. Air-gapped deployment with Azure AI Foundry in the customer's Azure tenant satisfies data residency requirements while enabling AI-powered triage and remediation.
- **Healthcare** -- HIPAA requirements for protected health information (PHI) proximity. Self-hosted deployment with private LLM endpoints keeps all analysis within the healthcare organization's network boundary.

All three contexts share the same technical deployment. The difference is in the LLM provider choice and network topology.

## Installation

Air-gapped installation follows the same Helm deployment process with additional configuration for container image transfer to a local registry, private LLM endpoint settings, proxy configuration, and CA certificates. Preflight checks validate LLM endpoint connectivity and license server access before the first analysis runs. For the current installation procedure and common issues, see the [deployment guide](https://app.pixee.ai/docs/deploy) and [Enterprise Troubleshooting](/enterprise/troubleshooting).
