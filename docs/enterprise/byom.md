---
title: Bring Your Own Model
slug: /enterprise/byom
track: leader
content_type: guide
seo_title: Bring Your Own Model - Choose Your LLM Provider for Pixee
description: Configure Pixee with your preferred LLM provider. Supports OpenAI, Azure AI Foundry, Anthropic, and Azure Anthropic with hierarchical model routing.
sidebar_position: 8
---

Pixee lets you choose your LLM provider instead of locking you into a single vendor. Four provider families are supported: OpenAI, Azure AI Foundry, Anthropic, and Azure Anthropic. You own the API keys, pick the vendor, control the bill, and decide which model handles which task through seven named LLM routing tiers. This is the opposite of a black-box AI product.

## Supported Providers

| Provider             | Description                                           | Use Case                                                          |
| -------------------- | ----------------------------------------------------- | ----------------------------------------------------------------- |
| **OpenAI**           | Public API or OpenAI-compatible private endpoints     | General purpose; air-gapped deployments with a compatible gateway |
| **Azure AI Foundry** | Azure-hosted models in customer's Azure tenant        | Azure-centric enterprises with existing Azure agreements          |
| **Anthropic**        | Direct Anthropic API with Anthropic-optimized prompts | Teams preferring Anthropic models                                 |
| **Azure Anthropic**  | Anthropic models via Azure marketplace                | Azure-centric organizations that want Anthropic models            |

**Custom endpoint support** allows routing through enterprise API gateways. Custom header name/value pairs handle gateway authentication, so Pixee fits into your existing API management infrastructure.

**Provider-family-aware prompting** is a design decision worth understanding: when configured for Anthropic, Pixee uses Anthropic-optimized triage prompts -- not a lowest-common-denominator approach that treats all providers identically. This matters for triage accuracy and fix quality. Most single-model AI products cannot do this because they are built around a single provider.

## Hierarchical Model Routing

Seven named tiers let enterprises control which model handles which workflow stage. Each tier is independently configurable for model selection, endpoint, and effort level.

| Tier              | Purpose                                          | What You Control                                    |
| ----------------- | ------------------------------------------------ | --------------------------------------------------- |
| **Default**       | General-purpose calls                            | Model selection, endpoint                           |
| **Reasoning**     | Deep triage decisions requiring careful analysis | Higher-capability model for complex classifications |
| **Fast**          | Quick classification of straightforward findings | Lower-latency model for speed                       |
| **Web Search**    | External research augmentation                   | Model with web access capability                    |
| **SCA**           | Software composition analysis                    | Model tuned for dependency analysis                 |
| **Deep Research** | In-depth vulnerability investigation             | Research-capable model                              |
| **Codegen**       | Fix generation                                   | Generation strategy selection                       |

### Why This Matters

**Cost optimization.** Route simple classifications to cheaper, faster models. Reserve expensive, high-capability models for complex triage decisions that justify the cost. Your LLM bill reflects the actual complexity of each task, not a one-size-fits-all model choice.

**Quality optimization.** Complex multi-file vulnerabilities get a reasoning-capable model. Straightforward SQL injection patterns get a fast model. The right model for the right task.

**Latency control.** Speed-sensitive workflows (fast classification, initial triage) use low-latency models. Quality-sensitive workflows (deep triage, fix generation) use higher-capability models regardless of latency.

Most competitors in the AI-assisted AppSec space use a single model for all tasks. Hierarchical routing lets enterprises tune the cost-quality-latency surface per workflow stage.

## Configuration

**During installation:** Select your LLM provider through the admin console (embedded cluster) or Helm values (BYO Kubernetes). Provide the API key and endpoint URL.

**Per-tier model configuration:** After initial setup, assign specific models to each of the seven tiers based on your cost, quality, and latency requirements.

**Preflight checks:** Every provider configuration is validated at install time. Preflight checks catch LLM misconfiguration immediately -- not when your first analysis runs and fails. This is a small detail that saves hours of debugging.

**Switching providers:** LLM provider configuration can be changed after initial deployment through the admin console or Helm values update. No data migration or reprocessing is required.

## Governance Controls

Bring Your Own Model is not just a technical feature -- it is a governance feature.

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

## Frequently Asked Questions

### Can I bring my own LLM model with Pixee?

Yes. Pixee supports four LLM provider families: OpenAI, Azure AI Foundry, Anthropic, and Azure Anthropic. You configure your API keys and endpoint, and Pixee routes all AI inference through your account.

### Can I use different models for different tasks?

Yes. Seven named LLM tiers let you assign different models to triage, remediation, classification, research, and other workflow stages. This lets you balance cost, quality, and latency per task type.

### Does Pixee use Anthropic-optimized prompts for Anthropic models?

Yes. Pixee uses provider-family-aware prompting. When configured for Anthropic, the triage engine uses Anthropic-optimized prompt structures rather than a generic approach.

### What happens if my LLM provider is unavailable?

Pixee queues tasks and retries when the provider becomes available. Deterministic codemods that require no LLM continue functioning regardless of LLM availability.

### Can I use a self-hosted open-source model?

If your model exposes an OpenAI-compatible API endpoint, it can be configured as a provider. Quality of triage and remediation depends on model capability.
