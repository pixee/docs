---
title: Bring Your Own Model
slug: /enterprise/byom
track: leader
content_type: guide
seo_title: Bring Your Own Model - Choose Your LLM Provider for Pixee
description: Configure Pixee with your preferred LLM provider. Supports OpenAI, Anthropic, Azure AI Foundry, AWS Bedrock, Google Vertex AI, and more with hierarchical model routing.
sidebar_position: 8
---

Pixee lets you choose your LLM provider instead of locking you into a single vendor. You own the API keys, pick the vendor, and control the bill. This is the opposite of a black-box AI product.

## Supported Providers

| Provider                           | Description                                                                                                                  |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **OpenAI**                         | Direct OpenAI API                                                                                                            |
| **Anthropic**                      | Direct Anthropic API with Anthropic-optimized prompts                                                                        |
| **Azure AI Foundry**               | Azure-hosted models in customer's Azure tenant (OpenAI and Anthropic models available)                                       |
| **AWS Bedrock**                    | AWS-hosted model marketplace in customer's AWS account                                                                       |
| **Google Cloud Vertex AI**         | Google Cloud-hosted model platform                                                                                           |
| **Oracle Cloud OCI Generative AI** | Oracle Cloud-hosted generative AI service                                                                                    |
| **Any OpenAI-compatible endpoint** | Self-hosted, private, or custom API gateway — covers air-gapped deployments, self-hosted models, and enterprise API gateways |

**Custom endpoint support** allows routing through enterprise API gateways. Custom header name/value pairs handle gateway authentication, so Pixee fits into your existing API management infrastructure.

**Provider-aware prompting:** Pixee optimizes prompts for each provider rather than using a one-size-fits-all approach. This matters for triage accuracy and fix quality.

## Supported Model Families

Each provider platform gives access to a broad and evolving set of model families. The list below is indicative — model availability expands continuously across platforms.

- **OpenAI models** — available via OpenAI and Azure AI Foundry
- **Anthropic Claude models** — available via Anthropic, AWS Bedrock, and Azure AI Foundry
- **Google Gemini models** — available via Google Cloud Vertex AI
- **Meta Llama models** — available via AWS Bedrock and self-hosted endpoints
- **Mistral models** — available via AWS Bedrock, Azure AI Foundry, and self-hosted endpoints
- **Amazon Nova models** — available via AWS Bedrock
- **Any model behind an OpenAI-compatible API** — self-hosted or custom

Model versions evolve rapidly. Pixee provides a current recommendation for each customer based on benchmarks across quality, speed, and cost. See [Model Recommendations](#model-recommendations) below.

## Model Recommendations

Pixee benchmarks model performance for security triage and fix generation tasks across quality, speed, and cost dimensions. The right model configuration depends on your cloud platform, compliance constraints, data residency requirements, and cost targets — there is no single best answer.

Based on your available cloud platforms and constraints, Pixee provides a recommended model configuration for your deployment. Contact your account team or [reach out here](https://pixee.ai/demo) for a model recommendation tailored to your environment.

## Hierarchical Model Routing

Pixee uses hierarchical routing to assign the right model capability to each task type — triage classification, deep reasoning, fix generation, and dependency analysis each have different requirements. You can assign different models to different task categories, letting you optimize for cost, latency, and quality independently.

**Cost optimization.** Route straightforward classifications to faster, cheaper models. Reserve high-capability models for complex decisions that justify the cost.

**Quality optimization.** Each task type gets a model matched to its requirements — not a single model handling everything.

**Latency control.** Speed-sensitive tasks use low-latency models. Quality-sensitive tasks use higher-capability models regardless of latency.

Contact your account team for guidance on model-to-task assignment for your deployment.

## Configuration

**During installation:** Select your LLM provider through the admin console (embedded cluster) or Helm values (BYO Kubernetes). Provide the API key and endpoint URL.

**Per-task model configuration:** After initial setup, assign specific models to each task category based on your cost, quality, and latency requirements.

**Preflight checks:** Every provider configuration is validated at install time. Preflight checks catch LLM misconfiguration immediately -- not when your first analysis runs and fails. This is a small detail that saves hours of debugging.

**Switching providers:** LLM provider configuration can be changed after initial deployment through the admin console or Helm values update. No data migration or reprocessing is required.

## Governance Controls

Bring Your Own Model is not just a technical feature — it is a governance feature.

| Control             | Detail                                                                                                                             |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| **Key ownership**   | Customer owns all API keys. Pixee never stores or accesses customer LLM credentials.                                               |
| **Traffic routing** | All LLM traffic routes through the customer's account. Pixee does not proxy LLM calls for self-hosted deployments.                 |
| **Cost visibility** | LLM usage appears on the customer's standard cloud billing. No hidden costs or Pixee-side LLM charges for self-hosted deployments. |
| **Audit trail**     | Every triage decision includes the LLM justification. Auditors can see what the model was asked and what it answered.              |

For full data flow details and credential handling, see [Security Architecture](/enterprise/security-architecture).

## LLM Resilience

When an LLM provider is unavailable, Pixee handles the degradation:

- **Task queuing.** Analysis tasks are queued and retried automatically when the provider becomes available. No manual intervention is needed.
- **Deterministic codemods continue.** Deterministic codemods that require no LLM involvement function regardless of LLM availability. A provider outage does not stop all remediation -- it stops AI-powered remediation only.
- **Existing results are unaffected.** Triage decisions and PRs that have already been delivered are not affected by provider unavailability. Historical data persists independently.

This resilience architecture means an LLM outage degrades Pixee's capability without halting it entirely.
