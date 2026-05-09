---
title: AI Settings
slug: /configuration/ai-settings
track: dev
content_type: guide
seo_title: AI Settings -- Pixee Docs
description: Configure triage sensitivity, fix quality thresholds, and LLM provider settings for Pixee triage and remediation.
sidebar_position: 7
---

# AI Settings

Pixee's AI settings let you control how aggressively the triage engine classifies findings and how the remediation engine generates fixes. Adjust triage sensitivity to match your team's false positive tolerance, configure which finding categories receive AI-powered analysis versus deterministic codemods, and set quality thresholds for fix acceptance. Enterprise deployments can additionally configure LLM providers and model routing.

## What AI Settings Control

AI settings govern two behaviors:

1. **Triage Automation behavior.** How aggressively Pixee classifies findings as true positives, false positives, or won't-fix. Higher sensitivity catches more issues but may surface more borderline findings.
2. **Remediation Automation behavior.** Which finding types receive AI-generated fixes versus deterministic code transformations (codemods), and the quality threshold fixes must meet before being presented as PRs.

These settings tune behavior. They do not bypass validation. Every fix Pixee generates -- whether from a deterministic codemod or an AI-powered fix -- passes through the same multi-layer evaluation pipeline before reaching your PR queue.

## Security Gates vs. Guardrails

This distinction matters for understanding what AI settings do and do not control.

**Security gates** block deployments when thresholds are exceeded. Your CI/CD pipeline owns these -- Pixee does not replace your existing gates.

**Guardrails** guide behavior without blocking. Pixee's AI settings act as guardrails that tune how aggressively Triage Automation and Remediation Automation operate. They shape what Pixee proposes; your team and your CI pipeline decide what gets merged and deployed.

Pixee operates as a guardrail layer. It proposes fixes through PRs. Your existing gates (CI checks, code review, deployment policies) remain in control of what ships.

## Triage Settings

Triage settings control how Pixee classifies scanner findings.

| Setting              | What It Controls                                                                                                             |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Triage sensitivity   | How aggressively findings are classified. Higher sensitivity surfaces more findings; lower sensitivity is more conservative. |
| Category controls    | Enable or disable triage for specific finding types (SAST, SCA, secrets, etc.)                                               |
| Finding type filters | Which CWE categories receive AI-powered triage analysis                                                                      |

### How sensitivity affects results

- **Conservative:** Fewer findings surfaced. Pixee only classifies findings it has high confidence in. Good for teams new to automated triage who want to build trust incrementally.
- **Balanced (default):** Moderate confidence threshold. Surfaces the majority of actionable findings while filtering obvious false positives.
- **Aggressive:** Surfaces more findings, including borderline cases. Useful for teams with mature triage workflows who want maximum coverage.

### Relationship to scanner quality

Triage accuracy depends on the quality of scanner input. Pixee integrates with a growing list of named scanner integrations and accepts any SARIF-producing scanner via universal SARIF import. Higher-quality scanner output yields higher-confidence triage results.

## Remediation Settings

Remediation settings control how Pixee generates fixes.

| Setting           | What It Controls                                                              |
| ----------------- | ----------------------------------------------------------------------------- |
| Fix categories    | Which CWE categories receive automated fixes                                  |
| Fix mode          | Whether a category uses deterministic codemods, AI-powered fixes, or both |
| Quality threshold | Minimum evaluation score a fix must meet before being presented as a PR       |

### The hybrid model

Pixee uses a hybrid approach to fix generation:

- **Deterministic codemods** apply well-known, deterministic code transformations. No LLM involved. These are the same open-source transformations available through [Codemodder](/open-source/codemodder).
- **AI-powered fixes** handle complex scenarios where deterministic patterns are insufficient. These use LLM-powered analysis to understand context and generate fixes.

By default, both modes are active. You can disable AI-powered fixes entirely and run only deterministic codemods, or restrict AI-powered fixes to specific CWE categories.

### Gradual automation

The recommended approach is progressive expansion:

1. **Start conservative.** Enable deterministic codemods only. Review merge rates and fix quality.
2. **Expand by category.** Enable AI-powered fixes for specific CWE categories where your team sees high fix quality.
3. **Broaden over time.** As confidence builds (tracked via merge rate and quality scores in [Reporting](/configuration/operations)), expand the scope of AI-powered fixes.

The [Phased Rollout Guide](/enterprise/phased-rollout) covers this progression in detail.

## Enterprise AI Configuration

Self-hosted Pixee deployments have additional AI configuration beyond the behavioral settings described above:

- **Bring Your Own Model (BYOM).** Choose your LLM provider (OpenAI, Azure AI Foundry, Anthropic, Azure Anthropic). Own your keys and control costs. See [Enterprise > BYOM](/enterprise/byom).
- **Model routing.** Enterprise deployments can route different analysis tasks to different models, balancing cost, latency, and quality per workflow stage.
- **Data flow controls.** Control what data reaches the LLM and through which network path. See [Enterprise > Security Architecture](/enterprise/security-architecture).

These infrastructure-level settings are managed through the admin console or Helm values, not through the Pixee dashboard's AI settings page.

