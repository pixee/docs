---
title: Compliance
slug: /enterprise/compliance
track: leader
content_type: conceptual
seo_title: Compliance - SOC 2, HIPAA, FedRAMP, PCI-DSS, and NIST 800-53 Mapping
description: Pixee compliance mapping for SOC 2, HIPAA, FedRAMP, PCI-DSS, NIST 800-53, and ISO 27001. Covers audit evidence, data residency, and AI governance.
sidebar_position: 6
---

Pixee supports compliance requirements by providing audit-ready evidence for every triage decision and remediation action. Every finding classification includes a timestamped, reasoned record with LLM justification. Every fix is delivered as a traceable pull request with full diff visibility. This page maps Pixee capabilities to SOC 2, HIPAA, FedRAMP, PCI-DSS, NIST 800-53, and ISO 27001 control requirements.

## How Pixee Supports Compliance

Pixee's compliance value rests on four architectural properties:

**Audit trail.** Every triage decision is persisted with a timestamp, the classification outcome (true positive, false positive, won't fix), and the LLM justification that produced the verdict. This record exists for the lifetime of the deployment and is backfilled for findings analyzed before the audit feature was added.

**Traceability.** Every fix is a Git commit within a pull request. The PR includes the proposed diff, quality scores (safety, effectiveness, cleanliness), the vulnerability that triggered the fix, and the merge status. Standard Git history provides the full chain from finding to resolution.

**No bypass.** The PR-only workflow is an architectural constraint, not an optional setting. All changes go through your existing code review, CI/CD pipelines, and branch protection rules. Pixee adds validation layers before your existing gates -- it does not bypass them.

**Compliance acceleration.** Automated triage and remediation help organizations meet contractual timeframes for critical and high-severity findings. Banking and healthcare teams with two-month remediation windows have reported that automation changes the math from "physically impossible" to "consistently achievable."

## Framework Mapping

The table below maps Pixee capabilities to specific controls in six compliance frameworks. Pixee describes how its capabilities align with these controls -- not claims of formal certification unless explicitly stated.

| Framework                          | Relevant Controls                                                                                                                                     | How Pixee Supports                                                                                                                                                                                                                                                                      |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **SOC 2 Type II**                  | CC6.1 (logical access controls), CC7.1 (system monitoring), CC8.1 (change management)                                                                 | Audit-ready triage records with timestamped justification. PR-based change tracking for every remediation. Role-based access via SSO (Google, Microsoft Entra ID, Okta). Every disposition persisted for control sampling.                                                              |
| **HIPAA**                          | 164.312(a)(1) access control, 164.312(c)(1) integrity controls, 164.312(d) authentication                                                             | Self-hosted deployment keeps PHI-adjacent data in customer network. SSO integration. Audit trail for all triage and remediation actions. PR workflow preserves change integrity.                                                                                                        |
| **FedRAMP**                        | AC-2 (account management), AU-2 (auditable events), CM-3 (configuration change control)                                                               | Air-gapped deployment with no source code leaving the network. Comprehensive audit event logging. Configuration changes documented through PR workflow.                                                                                                                                 |
| **PCI-DSS**                        | 6.3 (secure development), 6.5 (common vulnerability remediation), 10.2 (audit trails)                                                                 | Automated vulnerability remediation with full audit evidence. Triage decisions provide evidence for vulnerability management requirements. PR history for change documentation.                                                                                                         |
| **NIST 800-53**                    | RA-5 (vulnerability monitoring and scanning), SA-11 (developer testing), SI-2 (flaw remediation)                                                      | Automated triage with classification evidence. Remediation with traceable fixes. Continuous monitoring via 12 native scanner integrations and triage automation.                                                                                                                        |
| **ISO 27001**                      | A.12.6.1 (management of technical vulnerabilities), A.14.2.2 (system change control)                                                                  | Vulnerability management automation with audit evidence. Change control integration through PR workflow. Exportable records for audit review.                                                                                                                                           |
| **OCC 2013-29** (Third-Party Risk) | Third-party risk management, vendor due diligence, ongoing monitoring                                                                                 | Pixee supports vendor risk assessment via documented security controls, data classification, and audit trail. Self-hosted deployment keeps all data within customer network.                                                                                                            |
| **FFIEC IT Examination Handbook**  | Outsourced Technology Services examination procedures                                                                                                 | Audit trail for vulnerability management lifecycle maps to examination procedures. Event-sourced triage decisions provide examiner-ready evidence.                                                                                                                                      |
| **NYDFS 23 NYCRR 500**             | 500.5 (vulnerability assessment), 500.6 (audit trail), 500.7 (access controls), 500.15 (data encryption), 500.17 (incident response and notification) | Cybersecurity requirements addressed via: access controls (500.7), audit trail (500.6), vulnerability assessment (500.5), and data encryption (500.15). Incident response (500.17) and notification handled via customer's existing IR process with Pixee audit data as evidence input. |

**SOC 2 receives the most detailed treatment** because it is the most frequently requested framework in enterprise evaluation. SOC 2 control sampling relies on evidence that every change is authorized, reviewed, and documented -- properties that Pixee's PR workflow provides by architectural design.

For the current status of Pixee's own SOC 2 certification, contact the Pixee team.

## Audit Evidence

Pixee generates and persists the following evidence for every analysis:

| Evidence Type           | What It Contains                                                                      | Export Format       |
| ----------------------- | ------------------------------------------------------------------------------------- | ------------------- |
| **Triage records**      | Classification (TP/FP/won't fix), LLM justification, timestamp, finding metadata      | CSV, JSON, API      |
| **Fix evidence**        | PR link, full diff, quality scores (safety, effectiveness, cleanliness), merge status | CSV, JSON, API      |
| **Activity feed**       | Event-sourced analysis history with outcome banners                                   | API (SSE streaming) |
| **Historical backfill** | Activity persistence backfilled for findings analyzed before audit features           | Automatic           |

Evidence is exportable via the reporting API in CSV and JSON formats for integration with compliance platforms and GRC tools. The API supports automated evidence collection workflows -- your compliance team does not need to manually extract data from the Pixee UI.

## Data Residency and Data Handling

Compliance-driven organizations frequently ask where data lives. The answer depends on your deployment model:

| Deployment Model     | Data Residency                               | LLM Data Handling                                   |
| -------------------- | -------------------------------------------- | --------------------------------------------------- |
| **Cloud SaaS**       | Pixee cloud (see Pixee data handling policy) | Pixee-managed LLM providers                         |
| **Embedded Cluster** | Customer network                             | Customer's LLM provider in customer's chosen region |
| **Helm / BYO K8s**   | Customer network                             | Customer's LLM provider in customer's chosen region |
| **Air-Gapped**       | Customer network (isolated)                  | Customer's private LLM endpoint                     |

For self-hosted deployments, source code and scanner findings stay in the customer's network. LLM inference uses the customer's chosen provider in the customer's chosen region. The only outbound connection is license validation, which can be proxied.

**Banking teams** with data residency requirements: self-hosted deployment keeps all analysis data within your network perimeter. **Healthcare teams** with HIPAA requirements: the same applies, with the additional benefit of audit-ready evidence for vulnerability management controls. **Federal teams** with FedRAMP requirements: air-gapped deployment provides the strictest data isolation. See [Air-Gapped Deployment](/enterprise/air-gap) for capabilities and limitations.

For full data flow details, see [Security Architecture](/enterprise/security-architecture).

## Responsible AI Governance

For organizations with AI governance committees or Responsible AI councils:

The architecture provides verifiable answers to common governance questions:

- **Multiple documented validation layers** -- constrained generation, independent evaluation, PR review, CI/CD testing, SAST re-scanning
- **Human-in-the-loop** -- PR-only workflow is an architectural constraint, not a configuration option
- **No bypass of existing governance gates** -- Pixee adds layers before your existing review process
- **Narrow scope** -- security fixes only (1-5 lines applying OWASP/SANS patterns), not general-purpose code generation
- **Deterministic floor** -- deterministic codemods use zero LLM involvement with zero hallucination risk (see [Codemodder](/open-source/codemodder) for the full catalog)

For the full technical trust framework, see [Security & Trust](/platform/security) and [Fix Safety & Validation](/how-it-works/fix-safety).

## Frequently Asked Questions

### How does Pixee help with SOC 2 compliance?

Pixee provides audit-ready evidence for vulnerability management controls: timestamped triage decisions with reasoned justification, PR-based remediation with full change tracking, and exportable reports for control sampling. Every disposition is persisted for the lifetime of the deployment.

### Is Pixee SOC 2 Type II certified?

Contact the Pixee team for the current status of SOC 2 certification.

### Does Pixee support FedRAMP requirements?

Pixee supports FedRAMP-relevant controls through air-gapped deployment (no source code leaves your network), audit event logging, and configuration change documentation. See [Air-Gapped Deployment](/enterprise/air-gap) for disconnected environment details and known limitations.

### How does Pixee handle data residency requirements?

Self-hosted deployments keep all data in the customer's network. LLM inference uses the customer's chosen provider in the customer's chosen region. The only outbound connection is license validation, which can be proxied.

### Can Pixee generate compliance reports automatically?

Yes. Pixee's reporting API exports triage decisions, fix outcomes, and audit trails in CSV and JSON formats for integration with compliance platforms and GRC tools.
