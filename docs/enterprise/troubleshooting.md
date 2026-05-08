---
title: Enterprise Troubleshooting
slug: /enterprise/troubleshooting
track: leader
content_type: reference
seo_title: Enterprise Troubleshooting - Common Deployment and Operational Issues
description: "Troubleshoot common Pixee enterprise deployment issues: installation failures, scanner connectivity, LLM configuration, SSO, and performance."
sidebar_position: 11
---

This page covers the most common issues encountered during Pixee Enterprise deployment and operation. Each entry describes the symptom, likely cause, and resolution steps. Issues are organized by deployment phase: installation, scanner connectivity, LLM configuration, authentication, and day-two operations. If your issue is not listed here, contact Pixee solutions engineering.

## Installation Issues

| Symptom                                     | Likely Cause                               | Resolution                                                                                                                                                        |
| ------------------------------------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Embedded cluster install hangs or times out | Insufficient system resources              | Verify minimum requirements: 8 vCPU, 32 GB RAM, 100 GB+ SSD/NVMe with under 10 ms write latency. Check disk I/O performance.                                      |
| Helm install fails with image pull errors   | Container registry access not configured   | Verify image pull secrets are created in the Pixee namespace and the cluster can reach the container registry.                                                    |
| Air-gapped install fails to start           | Missing container images in local registry | Verify all required images have been transferred to the local registry and are tagged correctly. Compare against the image manifest.                              |
| KOTS admin console is inaccessible          | Port forwarding or firewall rules          | Verify port 30000 is accessible from your browser. Check firewall rules and any network policies that may block the admin console port.                           |
| Install completes but UI is unreachable     | TLS configuration mismatch                 | Verify the domain and TLS configuration in the admin console matches your DNS and certificate setup. Self-signed certificates require browser trust or exception. |

**Minimum Requirements Quick Check:** Before troubleshooting any installation issue, confirm: 8 vCPU, 32 GB RAM, 100 GB+ SSD/NVMe disk, ports 443 and 30000 open (embedded cluster) or port 443 open (Helm). Most installation failures trace back to insufficient resources or network access.

For detailed setup procedures, see [Embedded Cluster](/enterprise/embedded-cluster), [Helm / BYO Kubernetes](/enterprise/helm), or [Air-Gapped Deployment](/enterprise/air-gap).

## Scanner Connectivity

| Symptom                                 | Likely Cause                                                        | Resolution                                                                                                           |
| --------------------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Scanner findings not appearing in Pixee | SARIF file format mismatch or upload path error                     | Verify the scanner output conforms to the SARIF specification and the upload endpoint is correctly configured. |
| Partial findings ingestion              | Scanner output exceeds size limits or contains unsupported rule IDs | Check the scanner output for unsupported finding types. Verify the scanner is producing complete SARIF output.       |
| Duplicate findings after re-scan        | Deduplication key mismatch between scan runs                        | Verify the scanner configuration produces consistent finding identifiers across runs.                                |
| Findings appear but no fixes generated  | Scanner findings are in an unsupported language or CWE category     | Check the [Languages Overview](/languages/overview) for supported language and finding type coverage.                |

For scanner-specific setup guides, see [Integrations Overview](/integrations/overview). For custom scanner configuration, see the [Universal SARIF](/integrations/sarif-universal) guide.

## LLM Configuration

| Symptom                                   | Likely Cause                                    | Resolution                                                                                                                                                                              |
| ----------------------------------------- | ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Fixes not generating                      | LLM endpoint unreachable or credentials invalid | Verify the LLM endpoint URL is correct and the API key is valid. Run the preflight check from the admin console to test connectivity.                                                   |
| Slow fix generation                       | LLM provider rate limits or network latency     | Check your provider's rate limit status. Verify the network path between the Pixee cluster and the LLM endpoint has acceptable latency.                                                 |
| Air-gapped LLM not responding             | Private LLM endpoint misconfigured              | Verify the endpoint is accessible from within the cluster network namespace. Check proxy configuration if the endpoint requires proxy access.                                           |
| Triage decisions seem inaccurate          | LLM model capability insufficient               | The quality of triage and remediation depends on the model at the configured endpoint. Lower-capability models produce lower accuracy. Review the model assigned to the Reasoning tier. |
| Preflight check fails during installation | Endpoint URL, API key, or network path error    | Read the preflight error message carefully -- it specifies whether the issue is authentication, connectivity, or configuration.                                                         |

For LLM provider setup details, see [Bring Your Own Model](/enterprise/byom).

## Authentication and Access

| Symptom                                      | Likely Cause                | Resolution                                                                                                                                                    |
| -------------------------------------------- | --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SSO login fails                              | OIDC configuration mismatch | Verify the issuer URL, client ID, and callback URL match between Pixee and your identity provider configuration.                                              |
| Users can log in but cannot see repositories | SCM permissions not synced  | Re-sync repository access from the SCM platform. Verify the service account or GitHub App has access to the expected repositories.                            |
| Role assignment not working                  | RBAC misconfiguration       | Check user role assignments in the admin console. Verify the identity provider is sending the expected role claims.                                           |
| SSO redirect loop                            | Callback URL mismatch       | Verify the callback URL configured in Pixee matches the redirect URI registered with your identity provider exactly, including protocol and trailing slashes. |

For SSO configuration details, see [Security Architecture](/enterprise/security-architecture).

## Day-Two Operations

| Symptom                                   | Likely Cause                                       | Resolution                                                                                                                     |
| ----------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| High disk usage                           | Log retention or metrics storage growing unbounded | Adjust log retention settings in the admin console. Configure metric pruning intervals. Review support bundle log size limits. |
| Grafana dashboards not loading            | Observability subchart disabled or misconfigured   | Verify the Grafana subchart is enabled. If using BYO observability, verify telemetry is flowing to your platform.              |
| Upgrade fails                             | Helm values conflict with new version              | Review release notes for breaking changes before upgrading. Back up your values file before running the upgrade.               |
| Support bundle is too large               | Default log collection scope too broad             | Configure support bundle log size and age limits before generating. Narrow the collection scope to the relevant time window.   |
| Analysis queue growing without processing | LLM endpoint degraded or rate limited              | Check LLM endpoint health and rate limit status. Review the error rate in the observability dashboard.                         |

For monitoring configuration, see [Observability](/enterprise/observability).

## Getting Help

If your issue is not covered on this page:

1. **Generate a support bundle** from the KOTS admin console (embedded cluster) or using the support bundle tool (Helm). Configure log size and age limits before generation to control bundle size.

2. **Contact Pixee solutions engineering** with:
   - Deployment model (embedded cluster, Helm, air-gapped)
   - Pixee version (visible in admin console or Helm release)
   - Symptom description and when it started
   - Support bundle (attached)

3. **For critical issues** affecting production analysis, escalate through your enterprise support channel for priority response.
