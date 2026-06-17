---
title: SARIF Reference
slug: /api/sarif
track: dev
content_type: reference
seo_title: SARIF Reference -- Pixee Docs
description: How Pixee consumes SARIF from scanners. Field mapping, required fields, validation, and integration examples.
sidebar_position: 2
---

# SARIF Reference

SARIF (Static Analysis Results Interchange Format) is the OASIS standard that Pixee uses to ingest security findings from its named scanner integrations and any SARIF-producing tool. Pixee reads SARIF files to understand what vulnerabilities were found, where they are located, and what dataflow information is available -- then routes each finding to the appropriate triage and remediation engine. This page documents how Pixee consumes SARIF.

## What is SARIF?

SARIF is an [OASIS open standard](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) for representing static analysis tool output. It provides a common JSON format for any scanner to express findings, locations, code flows, and rule metadata.

Pixee supports **SARIF version 2.1.0**, the current stable release of the standard.

SARIF matters to Pixee's architecture because it enables scanner-agnostic remediation. Rather than building custom parsers for every scanner output format, Pixee normalizes all findings through SARIF. Any tool that produces valid SARIF can feed findings into Pixee for triage and remediation.

## How Pixee uses SARIF

```
Scanner  -->  SARIF file  -->  Pixee ingestion  -->  Triage  -->  Fix  -->  PR
```

1. **Ingestion.** SARIF files arrive via webhook from native scanner integrations, via the Universal SARIF integration, or via API upload.
2. **Normalization.** Scanner-specific handlers extract maximum metadata from each tool's SARIF output. When a native handler does not exist, the Universal SARIF handler processes any valid SARIF document.
3. **Triage routing.** Normalized findings enter the three-tier triage engine. Findings with richer SARIF data (code flows, related locations) receive higher-quality triage and remediation.
4. **Output.** Remediation results are delivered as pull requests on the target repository.

## Required and optional SARIF fields

Pixee reads specific SARIF fields to route findings and generate fixes. Richer SARIF input produces better results.

### Required fields

These fields must be present for Pixee to process a finding:

| SARIF Field                                                          | Type    | Pixee Usage                                             |
| -------------------------------------------------------------------- | ------- | ------------------------------------------------------- |
| `runs[].tool.driver.name`                                            | string  | Scanner identification and handler routing              |
| `runs[].results[].ruleId`                                            | string  | Rule matching for fix routing and knowledge base lookup |
| `runs[].results[].message.text`                                      | string  | Finding description for triage context                  |
| `runs[].results[].locations[].physicalLocation.artifactLocation.uri` | string  | File path of the vulnerability                          |
| `runs[].results[].locations[].physicalLocation.region.startLine`     | integer | Line number of the vulnerability                        |

### Recommended fields

These fields are not required, but significantly improve triage accuracy and fix quality:

| SARIF Field                                  | Type   | Pixee Usage                                                           |
| -------------------------------------------- | ------ | --------------------------------------------------------------------- |
| `runs[].results[].codeFlows[]`               | array  | Dataflow and taint propagation paths. Enables cross-file fix context. |
| `runs[].results[].codeFlows[].threadFlows[]` | array  | Step-by-step execution paths through the vulnerability                |
| `runs[].results[].relatedLocations[]`        | array  | Additional code context (sink locations, intermediate variables)      |
| `runs[].results[].level`                     | string | Severity classification (`error`, `warning`, `note`)                  |
| `runs[].tool.driver.rules[]`                 | array  | Rule metadata including descriptions and help text                    |
| `runs[].tool.extensions[]`                   | array  | Extension packs with additional rule documentation                    |

### Optional fields

| SARIF Field                            | Type   | Pixee Usage                                            |
| -------------------------------------- | ------ | ------------------------------------------------------ |
| `runs[].results[].fingerprints`        | object | Finding deduplication across scans                     |
| `runs[].results[].partialFingerprints` | object | Fuzzy matching for findings that shift between scans   |
| `runs[].results[].suppressions[]`      | array  | Previously suppressed findings (Pixee respects these)  |
| `runs[].results[].properties`          | object | Custom scanner metadata preserved through the pipeline |

## Dataflow quality and fix quality

The richness of SARIF `codeFlows` data directly affects fix quality. Pixee classifies dataflow quality into four tiers:

| Tier                   | SARIF Signal                                           | Fix Impact                                                                               |
| ---------------------- | ------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| **STRONG_MULTI_FILE**  | `codeFlows` with `threadFlows` spanning multiple files | Highest fix quality. Cross-file context enables precise remediation.                     |
| **STRONG_SINGLE_FILE** | `codeFlows` with `threadFlows` within a single file    | High fix quality. Full taint path available for context-aware fixes.                     |
| **WEAK**               | Partial or low-confidence `codeFlows`                  | Moderate fix quality. Pixee uses heuristics to supplement incomplete paths.              |
| **SINGLE_LOCATION**    | Only `locations[]`, no `codeFlows`                     | Baseline fix quality. Pixee relies on rule knowledge base and surrounding code analysis. |

**Recommendation:** Configure your scanner to export `codeFlows` and `threadFlows` when available. CodeQL and Semgrep produce rich dataflow by default. Some scanners require explicit configuration to include flow data in SARIF output.

## SARIF validation

Pixee validates incoming SARIF documents against the 2.1.0 schema before processing.

**Common validation failures:**

| Issue                               | Cause                                          | Fix                                                                                     |
| ----------------------------------- | ---------------------------------------------- | --------------------------------------------------------------------------------------- |
| Missing `runs` array                | Malformed SARIF document                       | Ensure the top-level object contains a `runs` array with at least one run               |
| Empty `results`                     | Scanner found no findings                      | Expected behavior -- Pixee logs the scan but generates no fixes                         |
| Missing `locations` on a result     | Scanner omitted location data                  | Configure scanner to include file and line information                                  |
| Invalid `uri` in `artifactLocation` | Path uses backslashes or absolute system paths | Use forward slashes and repository-relative paths                                       |
| Missing `ruleId`                    | Scanner omitted the rule identifier            | Ensure scanner output includes rule IDs. Pixee cannot route findings without a rule ID. |

Validate your SARIF files before upload using the [SARIF Multitool](https://github.com/microsoft/sarif-sdk):

```bash
sarif validate my-results.sarif
```

## Integration examples

### Upload SARIF via API

```bash
curl -X POST \
     -H "Authorization: Bearer $PIXEE_TOKEN" \
     -H "Content-Type: application/json" \
     -d @scanner-results.sarif \
     https://app.pixee.ai/api/v1/repositories/REPO_ID/sarif
```

### Python: Upload and poll for results

```python
import requests
import time

TOKEN = "YOUR_API_TOKEN"
BASE = "https://app.pixee.ai/api/v1"
REPO_ID = "your-repo-id"
headers = {"Authorization": f"Bearer {TOKEN}"}

# Upload SARIF
with open("scanner-results.sarif", "r") as f:
    sarif_data = f.read()

upload = requests.post(
    f"{BASE}/repositories/{REPO_ID}/sarif",
    headers={**headers, "Content-Type": "application/json"},
    data=sarif_data
)
scan_id = upload.json()["scan_id"]

# Poll for completion
while True:
    status = requests.get(
        f"{BASE}/repositories/{REPO_ID}/scans/{scan_id}",
        headers=headers
    ).json()

    if status["state"] in ("completed", "failed"):
        break
    time.sleep(10)

print(f"Scan {status['state']}: {status.get('fixes_generated', 0)} fixes generated")
```

### CI/CD pipeline: Scanner to Pixee to PR

```yaml
# GitHub Actions example
- name: Run CodeQL
  uses: github/codeql-action/analyze@v3
  with:
    output: sarif-results

- name: Upload to Pixee
  run: |
    curl -X POST \
         -H "Authorization: Bearer ${{ secrets.PIXEE_TOKEN }}" \
         -H "Content-Type: application/json" \
         -d @sarif-results/results.sarif \
         https://app.pixee.ai/api/v1/repositories/${{ vars.PIXEE_REPO_ID }}/sarif
```

## Scanner-specific SARIF notes

Native scanner integrations handle SARIF automatically. These notes apply when you generate SARIF manually or use the Universal SARIF integration.

| Scanner       | SARIF Notes                                                                                                                                                 |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CodeQL**    | Produces rich SARIF with `codeFlows`, `threadFlows`, and `tool.extensions[].rules[].help.markdown`. Pixee extracts all of these for maximum triage context. |
| **Semgrep**   | Exports SARIF via `semgrep --sarif`. Rule explanations are in `fullDescription.text`. Include `--verbose` for richer output.                                |
| **SonarQube** | SARIF export varies by edition. Ensure `codeFlows` are included when available.                                                                             |
| **Checkmarx** | Produces metadata-sparse SARIF. Pixee compensates with rule-ID-based prompting from its knowledge base.                                                     |
| **Snyk**      | Use `snyk code test --sarif` for SAST results.                                                                                                              |
| **Trivy**     | Use `trivy fs --format sarif` for filesystem scanning results.                                                                                              |

For full setup guides per scanner, see [Integrations Overview](/integrations/overview).

## Related pages

- [API Overview](/api/overview) -- Authentication and endpoint reference
- [Universal SARIF Integration](/integrations/sarif-universal) -- Setup guide for SARIF ingestion
- [Integrations Overview](/integrations/overview) -- All supported scanners
- [Scanner Integration](/platform/scanner-integration) -- Technical depth on scanner normalization
