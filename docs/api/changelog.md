---
title: Changelog
slug: /api/changelog
track: dev
content_type: reference
seo_title: Changelog -- Pixee Docs
description: "Pixee platform changelog: new features, improvements, bug fixes, and API changes."
sidebar_position: 4
---

# Changelog

This changelog tracks all notable changes to the Pixee platform, including new language support, scanner integrations, API updates, and bug fixes. Entries follow [Keep a Changelog](https://keepachangelog.com/) conventions and semantic versioning. For enterprise deployment-specific changes, see [Enterprise Troubleshooting](/enterprise/troubleshooting).

## Entry format

Each release follows this template:

```
## [Version] - YYYY-MM-DD

### Added
- New features and capabilities

### Changed
- Changes to existing functionality

### Fixed
- Bug fixes

### Deprecated
- Features marked for future removal

### Removed
- Features removed in this release

### Security
- Security-related changes and patches
```

Categories are omitted when a release has no entries of that type.

---

## [5.4.22] - 2026-04-14

### Added

- **OpenAI Responses API support.** New API type toggle for OpenAI providers supporting the `/v1/responses` endpoint in addition to the existing `/v1/chat/completions` endpoint. Configure via the LLM provider settings in the admin console.
- **TLS-intercepting proxy CA certificate injection.** Enterprise deployments behind TLS-intercepting proxies can now inject custom CA certificates into the analysis service HTTP clients. Resolves connectivity failures in environments with mandatory traffic inspection. See [Enterprise Deployment](/enterprise/deployment).

### Changed

- SCA model preflight validation now aligns across all LLM provider families (OpenAI, Azure AI Foundry, Anthropic, Azure Anthropic), catching model misconfiguration at install time.

### Fixed

- CA certificate handling for analysis-service outbound connections in proxy-heavy environments (follow-up to v5.4.22 initial support).

---

## [5.4.15] - 2026-04-01

### Added

- **Datadog SAST integration.** Native scanner handler for Datadog SAST findings. Pixee now ingests SARIF from Datadog alongside the existing 11 native scanner integrations. See [Integrations Overview](/integrations/overview).
- **Activity feed with SSE streaming.** Triage outcomes and remediation activity are now streamed in real time via Server-Sent Events to the Pixee dashboard. Includes drawer auto-transition and outcome banners.

### Changed

- Activity persistence is now backfilled for findings analyzed before the activity feed was added. Historical triage decisions appear in the feed retroactively.

---

## [5.4.11] - 2026-03-24

### Added

- **Decision-tree triage analyzer.** New triage strategy option (`decision-tree`) for deterministic, rules-based triage routing. Complements existing ReACT and agent-based strategies.
- **Arnica SAST integration.** Native scanner handler for Arnica SAST findings. See [Integrations Overview](/integrations/overview).
- **Anthropic-optimized triage prompts.** Provider-family-aware prompting for Anthropic LLM providers. Triage prompts are now optimized per provider family rather than using a lowest-common-denominator approach.
- **Authentik IdP federation and RP-Initiated Logout.** Embedded Authentik OIDC provider now federates to upstream corporate identity providers (Google Workspace, Microsoft Entra ID, Okta) with auto-redirect and direct login. RP-Initiated Logout enables clean session termination.
- **Bring-your-own database secret support.** CloudNativePG now supports `existingSecret` for external secret managers (Vault, External Secrets Operator, SOPS). See [Enterprise Deployment](/enterprise/deployment).
- **Bitbucket API token migration.** Bitbucket authentication migrated from deprecated app passwords to API tokens. Supports Bitbucket Cloud and Server.
- **SCA smart fix strategies.** Improved dependency upgrade logic with breakage prediction for software composition analysis remediations.

### Changed

- Embedded cluster bumped to Replicated v2.13.3+ with Kubernetes 1.32 and upgrade-path fixes.
- Observability stack upgraded: VictoriaMetrics v1.138.0, Victoria-logs v1.48.0, Victoria-logs agent v1.48.0, Victoria-traces v0.8.0.
- Analysis-service now emits trace telemetry for distributed tracing through the observability stack.

---

## [5.6.0] - 2026-03-10 (Helm chart)

### Added

- **Helm chart v5.6.0** for BYO Kubernetes deployments (EKS, GKE, AKS, self-managed). Conditional subcharts for object storage, database, observability, and authentication. See [Enterprise Deployment](/enterprise/deployment).

### Changed

- Storage class matrix documented for EKS (`gp2`/`gp3`), GKE (`standard-rwo`), AKS (`managed-csi`), and K3s/local default.
- Pod-identity support (IRSA, workload identity) for object store credentials alongside static key configuration.

---

## [5.4.0] - 2026-02-15

### Added

- **Hierarchical LLM routing.** Seven named LLM tiers (default, reasoning, fast, web-search, SCA, deep-research, codegen) with per-tier model and endpoint configuration. Enables cost/quality/latency tuning per workflow stage.
- **Global concurrency control.** Process-wide semaphore for LLM calls prevents rate-limit (429) errors across all tiers and providers.
- **Backpressure management.** Proactive cancellation of analyses that cannot complete within platform timeout limits.

### Changed

- LLM provider configuration now supports custom endpoint URLs and custom header name/value pairs for authenticated enterprise gateways.

---

## Enterprise server versioning

Pixee Enterprise Server releases are versioned independently of the Pixee cloud platform. The Helm chart version (e.g., v5.6.0) and embedded cluster version share the same release notes.

| Deployment Model      | Version Source     | Update Method                         |
| --------------------- | ------------------ | ------------------------------------- |
| Cloud (SaaS)          | Automatic          | Managed by Pixee                      |
| Embedded Cluster      | KOTS admin console | One-click update via admin console    |
| Helm / BYO Kubernetes | Helm chart version | `helm upgrade` with new chart version |
| Air-gapped            | Offline bundle     | Download bundle, apply via KOTS       |

For upgrade procedures and troubleshooting, see [Enterprise Deployment](/enterprise/deployment) and [Enterprise Troubleshooting](/enterprise/troubleshooting).

## API versioning

API versions are independent of platform versions. The current API version is `v1`. Breaking API changes will ship under a new version prefix (`v2`) with a documented migration period.

Non-breaking additions (new fields in response bodies, new event types, new endpoints) are added to the current API version without a version bump.

## Subscribe to updates

- **Dashboard notifications:** Enable release notifications in **Settings > Notifications**.
- **GitHub releases:** Watch the [Pixee Enterprise Server releases](https://github.com/pixee/pixee-enterprise-server) for new version announcements.

## Related pages

- [API Overview](/api/overview) -- Endpoint reference and authentication
- [Enterprise Deployment](/enterprise/deployment) -- Upgrade procedures
- [Enterprise Troubleshooting](/enterprise/troubleshooting) -- Version-specific issues
- [Integrations Overview](/integrations/overview) -- Scanner integration details

## FAQ

### How often does Pixee release updates?

Pixee has shipped approximately 25 releases in the past 6 months across the enterprise server Helm chart, with regular updates to the cloud platform. Release cadence varies based on feature scope and customer needs.

### How do I know which version I am running?

For embedded cluster deployments, check the version in the KOTS admin console. For Helm deployments, run `helm list -n pixee` to see the deployed chart version. Cloud (SaaS) users are always on the latest version.

### Do I need to update my API integration when Pixee releases a new version?

Non-breaking additions (new response fields, new event types, new endpoints) do not require changes to existing integrations. Breaking changes ship under a new API version prefix with a documented migration period. Pin your integration to the current API version (`v1`) for stability.
