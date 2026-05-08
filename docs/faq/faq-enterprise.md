---
title: Enterprise Technical FAQ
slug: /faq/enterprise
track: both
content_type: faq
seo_title: Enterprise Technical FAQ -- Pixee Docs
description: Enterprise FAQ covering deployment, compliance, data residency, BYOM LLM configuration, and AI governance.
sidebar_position: 2
---

This page covers enterprise deployment, compliance, data residency, AI governance, and security architecture questions. If your question is not here, check the [General FAQ](/faq/general) for product capabilities or the [Troubleshooting FAQ](/faq/troubleshooting) for operational issues.

## Deployment and Infrastructure

### Does Pixee support self-hosted deployment?

See [Deployment Options](/enterprise/deployment) for details on all three self-hosted models (embedded cluster, Helm, air-gapped) and their architecture diagrams.

### Can Pixee run in an air-gapped environment?

See [Air-Gapped Deployment](/enterprise/air-gap) for details on capabilities, requirements, and known limitations in disconnected environments.

### What are the infrastructure requirements for self-hosted Pixee?

See [Deployment Options](/enterprise/deployment) for infrastructure requirements, sizing guidance, and deployment timelines per model.

### Does Pixee support multiple SCM platforms simultaneously?

Yes. A single Pixee Enterprise deployment supports GitHub, GitLab, Azure DevOps, and Bitbucket at the same time — 4 platforms from one instance. You do not need separate deployments per platform. Each SCM connection is configured independently through the admin console, and Pixee delivers the same triage and remediation capabilities across all of them.

### How does Pixee handle high availability and disaster recovery?

Pixee Enterprise runs on Kubernetes with standard HA patterns: pod replication, persistent volume claims, and configurable backup. The embedded cluster includes built-in backup and restore capabilities through the KOTS admin console. Helm deployments leverage your existing Kubernetes HA infrastructure — EKS, GKE, and AKS all have documented storage-class configurations. All triage decisions and fix history persist independently of the analysis pipeline, so operational state survives pod restarts and cluster failovers. The bundled observability stack (metrics, logs, traces, dashboards) provides visibility into platform health without requiring a separate monitoring purchase.

### What is Pixee's upgrade process?

Embedded cluster: upgrades via the KOTS admin console with one-click apply — no Kubernetes expertise required. Helm: standard `helm upgrade` with release notes documenting breaking changes. Air-gapped: new image bundles transferred to your registry, then the standard upgrade path applies. Pixee has shipped approximately 25 releases in 6 months, reflecting active development and rapid iteration. Each release includes documented changes, version-specific migration notes where applicable, and subchart version bumps for the bundled observability stack. The upgrade cadence means security coverage and triage accuracy improve continuously without requiring customer-side code changes.

## Data Handling and Residency

### How does Pixee handle data residency requirements?

See [Security Architecture](/enterprise/security-architecture) for the full data flow table by deployment model. Self-hosted deployments keep all data in your network. Air-gapped deployments have zero outbound data transmission. For cloud SaaS, contact Pixee for data handling details.

### Does Pixee access or store my source code?

Pixee analyzes code to generate fixes but does not store full repositories. Code snippets relevant to a specific finding are sent to your configured LLM provider — in self-hosted and air-gapped deployments, this traffic stays within your network. Only the vulnerable function and surrounding context are sent, not entire files or repositories. For dataflow findings, the taint flow steps are included. File paths sent to LLM providers are relative to the project root only. No absolute filesystem paths, repository URLs, git metadata, commit hashes, author information, CI/CD details, or scanner-specific identifiers are sent to LLM providers. Triage decisions store finding metadata, not source code. The audit trail references commits and PRs, not code content. Each analysis is a stateless inference call — no data persists across analyses at the LLM provider.

### What data does Pixee send to LLM providers?

Pixee sends code snippets — the vulnerable function and surrounding context — to the configured LLM provider for fix generation. For dataflow findings, the taint flow steps are included. In self-hosted and air-gapped deployments, this traffic stays within your network. Pixee does not send repository names, organizational metadata, or CI/CD configuration to LLM providers. Bring Your Own Model (BYOM) means you control the provider, the model, the endpoint, and the data path.

### Can I control which LLM provider Pixee uses?

Yes. Bring Your Own Model (BYOM) supports OpenAI, Azure AI Foundry, Anthropic, and Azure Anthropic. You choose the provider, the model, and the endpoint. For air-gapped deployments, you host the model entirely within your network. Pixee does not default to any external LLM — you configure the provider during deployment. Per-provider preflight checks validate the LLM connection at install time, not at first analysis, so misconfiguration is caught before any code is analyzed. Provider-family-aware prompting ensures optimal results for each provider rather than a lowest-common-denominator approach. Customer owns the keys, picks the vendor, keeps the bill.

## Compliance and Certification

### Is Pixee SOC 2 Type II certified?

Contact Pixee for current SOC 2 certification status and audit report availability. Pixee's architecture supports the controls required for SOC 2 Type II — including audit-ready evidence trails with timestamped triage justifications, role-based access control with SCM permission inheritance, and change management documentation through PR-based fix delivery with full diff tracking and quality scores. Enterprise customers can request compliance documentation through their account team.

### How does Pixee help with SOC 2 compliance?

See [Compliance](/enterprise/compliance) for the full framework mapping table covering SOC 2, HIPAA, FedRAMP, PCI-DSS, NIST 800-53, and ISO 27001.

### Does Pixee support FedRAMP requirements?

Pixee supports FedRAMP-relevant controls through air-gapped deployment (no source code leaves your network), audit event logging (AU-2), configuration change documentation (CM-3), and account management (AC-2). Air-gapped deployment with a private LLM eliminates all external data transmission. Contact Pixee for current FedRAMP authorization status and for details on how specific control families are addressed.

### How does Pixee map to HIPAA, PCI-DSS, and NIST 800-53?

See [Compliance](/enterprise/compliance) for the full framework mapping table with specific control references per framework.

### What audit trail does Pixee provide?

See [Compliance](/enterprise/compliance) for the full audit evidence breakdown including export formats, evidence types, and framework mapping.

### How does Pixee handle AI governance requirements?

Pixee is designed for AI governance committee review. Every AI-generated fix passes through documented validation layers before delivery -- constrained generation that limits the AI to established security patterns, independent evaluation by a separate model (not self-critique from the generator), and your existing code review process. The PR-based workflow ensures human-in-the-loop approval for every change. No AI output bypasses existing governance gates. Deterministic codemods use zero LLM involvement -- a significant portion of fixes carry no AI risk whatsoever. All decisions are auditable with persisted reasoning. See [Security Architecture](/enterprise/security-architecture) for the full AI governance architecture.

## Security Architecture

### How does Pixee authenticate users?

See [Security Architecture](/enterprise/security-architecture) for authentication options (SSO via Google Workspace, Microsoft Entra ID, Okta, embedded Authentik OIDC) and RBAC details.

### What is Pixee's security architecture?

See [Security Architecture](/enterprise/security-architecture) for data flow diagrams, access control details, credential management, AI governance, and network security.

### Has Pixee undergone third-party security assessment?

Contact Pixee for details on third-party security assessments, penetration test reports, and security audit results. Enterprise customers can request this documentation through their account team or during the evaluation process. Pixee's architecture is designed for security scrutiny — every code change is auditable, every AI decision is traceable, and every data path is documented. The self-hosted deployment model means your own security team can assess the platform running within your infrastructure using your standard evaluation methodology.

### How does Pixee handle secrets and credentials?

See [Security Architecture](/enterprise/security-architecture) for credential management details, including `existingSecret` support for Vault, External Secrets Operator, and SOPS.
