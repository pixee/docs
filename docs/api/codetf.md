---
title: CodeTF Specification
slug: /api/codetf
track: dev
content_type: reference
seo_title: CodeTF Specification -- Pixee Docs
description: "CodeTF (Code Transformation Format) open specification: schema definition, field reference, and integration examples."
sidebar_position: 2
---

# CodeTF Specification

CodeTF (Code Transformation Format) is an open specification created by Pixee for describing automated code changes in a structured, machine-readable format. CodeTF captures what changed, why it changed, and how the change was validated -- enabling audit trails, downstream automation, and integration with CI/CD pipelines. This page provides the complete schema definition, field reference, and integration examples.

## What is CodeTF?

Existing standards describe security findings (SARIF), dependencies (SBOM), and vulnerabilities (CVE/CWE). No standard existed for describing _what an automated fix actually did to your code_. CodeTF fills that gap.

CodeTF is the output format. SARIF is the input format. A scanner produces a SARIF file describing the problem. Pixee consumes that SARIF, generates a fix, and produces a CodeTF document describing the solution.

CodeTF is an open specification. Any tool can produce or consume CodeTF documents. The schema is publicly available on [GitHub](https://github.com/pixee/codemodder-specs).

## CodeTF vs SARIF

| Dimension     | SARIF                               | CodeTF                                |
| ------------- | ----------------------------------- | ------------------------------------- |
| Purpose       | Describes findings (problems)       | Describes fixes (changes)             |
| Direction     | Scanner output                      | Remediation output                    |
| Content       | Vulnerability location and metadata | Code diffs, rationale, and validation |
| Standard body | OASIS                               | Open specification by Pixee           |
| Use case      | Input to Pixee                      | Output from Pixee                     |
| Data model    | Runs, results, locations            | Run metadata, results, changesets     |

## Schema overview

A CodeTF document has three layers: run metadata, an array of results (one per codemod applied), and changesets within each result (one per file modified).

```
CodeTF Document
|-- version          (string)   Schema version
|-- run              (object)   Execution metadata
|   |-- vendor       (string)   Tool vendor
|   |-- tool         (string)   Specific engine (e.g., "codemodder-python")
|   |-- elapsed      (string)   Processing time
|   +-- commandLine  (string)   Invocation command
+-- results[]        (array)    Transformation results
    |-- codemod      (string)   Codemod identifier
    |-- summary      (string)   Human-readable fix description
    |-- description  (string)   Detailed explanation
    |-- references[] (array)    External references (CWE, OWASP)
    |-- properties   (object)   Custom key-value metadata
    |-- changeset[]  (array)    File-level changes
    |   |-- path     (string)   File path relative to repo root
    |   |-- diff     (string)   Unified diff
    |   |-- changes[](array)    Line-level change descriptions
    |   |   |-- lineNumber   (int)    Line number in modified file
    |   |   |-- description  (string) What changed at this line
    |   |   +-- properties   (object) Per-change metadata
    |   +-- ai       (boolean)  Whether AI was used for this change
    |-- detectionTool     (string)  Scanner that found the issue
    +-- fixedFindings[]   (array)   SARIF finding references resolved
```

## Field reference

### Top-level fields

| Field     | Type   | Required | Description                                                               |
| --------- | ------ | -------- | ------------------------------------------------------------------------- |
| `version` | string | Yes      | Schema version. Current: `"3.0.0"`                                        |
| `run`     | object | Yes      | Execution context for the transformation run                              |
| `results` | array  | Yes      | Array of transformation results. May be empty if no fixes were generated. |

### Run object

| Field             | Type   | Required | Description                                         |
| ----------------- | ------ | -------- | --------------------------------------------------- |
| `run.vendor`      | string | Yes      | Vendor name (e.g., `"pixee"`)                       |
| `run.tool`        | string | Yes      | Engine identifier (e.g., `"codemodder-python"`)     |
| `run.elapsed`     | string | No       | ISO 8601 duration or human-readable processing time |
| `run.commandLine` | string | No       | Command used to invoke the transformation           |

### Result object

| Field           | Type   | Required | Description                                                                           |
| --------------- | ------ | -------- | ------------------------------------------------------------------------------------- |
| `codemod`       | string | Yes      | Unique codemod identifier (e.g., `"pixee:python/secure-random"`)                      |
| `summary`       | string | Yes      | One-line human-readable fix description                                               |
| `description`   | string | Yes      | Detailed explanation of what the fix does and why                                     |
| `references`    | array  | No       | External references: `{"url": "https://cwe.mitre.org/...", "description": "CWE-330"}` |
| `properties`    | object | No       | Arbitrary key-value metadata for custom integrations                                  |
| `changeset`     | array  | Yes      | Array of file-level changes (at least one entry per result)                           |
| `detectionTool` | string | No       | Scanner that detected the original finding                                            |
| `fixedFindings` | array  | No       | Array of SARIF finding references this fix resolves                                   |

### Changeset object

| Field     | Type    | Required | Description                                                                      |
| --------- | ------- | -------- | -------------------------------------------------------------------------------- |
| `path`    | string  | Yes      | File path relative to repository root                                            |
| `diff`    | string  | Yes      | Unified diff of the change                                                       |
| `changes` | array   | No       | Line-level descriptions of individual changes                                    |
| `ai`      | boolean | No       | `true` if AI generated this change; `false` or absent for deterministic codemods |

### Change object

| Field         | Type    | Required | Description                      |
| ------------- | ------- | -------- | -------------------------------- |
| `lineNumber`  | integer | Yes      | Line number in the modified file |
| `description` | string  | Yes      | What changed at this line        |
| `properties`  | object  | No       | Additional per-change metadata   |

## Complete example

This example shows a CodeTF document for a Python fix that replaces `random.random()` with `secrets.token_hex()` to address CWE-330 (Use of Insufficiently Random Values):

```json
{
  "version": "3.0.0",
  "run": {
    "vendor": "pixee",
    "tool": "codemodder-python",
    "elapsed": "2.4s",
    "commandLine": "codemodder-python /repo --codemod=pixee:python/secure-random"
  },
  "results": [
    {
      "codemod": "pixee:python/secure-random",
      "summary": "Replaced insecure random with cryptographically secure alternative",
      "description": "The random module produces predictable pseudo-random values unsuitable for security contexts. This fix replaces random.random() with secrets.token_hex() for generating session tokens.",
      "references": [
        {
          "url": "https://cwe.mitre.org/data/definitions/330.html",
          "description": "CWE-330: Use of Insufficiently Random Values"
        },
        {
          "url": "https://owasp.org/www-community/vulnerabilities/Insecure_Randomness",
          "description": "OWASP: Insecure Randomness"
        }
      ],
      "properties": {},
      "changeset": [
        {
          "path": "src/auth/token_generator.py",
          "diff": "--- a/src/auth/token_generator.py\n+++ b/src/auth/token_generator.py\n@@ -1,5 +1,5 @@\n-import random\n+import secrets\n \n def generate_session_token():\n-    return str(random.random())\n+    return secrets.token_hex(32)",
          "changes": [
            {
              "lineNumber": 1,
              "description": "Replaced 'import random' with 'import secrets'"
            },
            {
              "lineNumber": 4,
              "description": "Replaced random.random() with secrets.token_hex(32) for cryptographic randomness"
            }
          ],
          "ai": false
        }
      ],
      "detectionTool": "codeql",
      "fixedFindings": [
        {
          "id": "py/insecure-randomness",
          "rule": "py/insecure-randomness"
        }
      ]
    }
  ]
}
```

## Consuming CodeTF in CI/CD

Parse CodeTF output to build compliance reports, track remediation progress, or gate deployments.

**Python: Extract fix summaries from a CodeTF document**

```python
import json
from pathlib import Path

codetf = json.loads(Path("codetf-output.json").read_text())

for result in codetf["results"]:
    files_changed = len(result["changeset"])
    ai_used = any(c.get("ai", False) for c in result["changeset"])

    print(f"Codemod: {result['codemod']}")
    print(f"  Summary: {result['summary']}")
    print(f"  Files changed: {files_changed}")
    print(f"  AI-generated: {ai_used}")
    print(f"  Detection tool: {result.get('detectionTool', 'N/A')}")
    print()
```

**Generate a compliance audit row per fix:**

```python
import csv
import json

codetf = json.loads(Path("codetf-output.json").read_text())

with open("audit-trail.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["codemod", "summary", "files", "ai_used", "references"])

    for result in codetf["results"]:
        refs = "; ".join(r["description"] for r in result.get("references", []))
        ai = any(c.get("ai", False) for c in result["changeset"])
        writer.writerow([
            result["codemod"],
            result["summary"],
            len(result["changeset"]),
            ai,
            refs
        ])
```

## Versioning

CodeTF uses semantic versioning. The current schema version is `3.0.0`.

| Version | Status    | Notes                                                         |
| ------- | --------- | ------------------------------------------------------------- |
| 3.0.0   | Current   | Pydantic-modeled schema, fix-quality ratings, package actions |
| 2.0.0   | Supported | Previous schema version                                       |

Breaking changes between major versions are documented in the [Changelog](/api/changelog). CodeTF documents always include a `version` field so consumers can branch on schema version at parse time.

## Open specification

CodeTF is open source and not proprietary to Pixee. The specification, Pydantic models, and tooling are available on GitHub:

- **Specification:** [github.com/pixee/codemodder-specs](https://github.com/pixee/codemodder-specs)
- **Python models:** [github.com/pixee/codemodder-python](https://github.com/pixee/codemodder-python)
- **Java models:** [github.com/pixee/codemodder-java](https://github.com/pixee/codemodder-java)

Contributions and integrations from the community are welcome.

## Related pages

- [API Overview](/api/overview) -- Authentication and endpoint reference
- [SARIF Reference](/api/sarif) -- The complementary input format
- [How Fix Generation Works](/how-it-works/fix-generation) -- Where CodeTF is generated
- [Fix Safety and Validation](/how-it-works/fix-safety) -- CodeTF captures validation metadata
- [Webhooks](/api/webhooks) -- Event triggers that include CodeTF payloads
- [Changelog](/api/changelog) -- Schema version history

## FAQ

### What is CodeTF format?

CodeTF (Code Transformation Format) is an open specification created by Pixee for describing automated code changes in a structured, machine-readable format. Each document captures the code diff, rationale, references (CWE, OWASP), and whether AI was used -- providing a complete audit trail for every automated fix.

### How does CodeTF differ from SARIF?

SARIF describes security findings (what is wrong). CodeTF describes security fixes (what changed and why). They are complementary: SARIF is the input to Pixee; CodeTF is the output. A typical pipeline flows from scanner to SARIF to Pixee to CodeTF to pull request.

### Is CodeTF proprietary to Pixee?

No. CodeTF is an open specification. The schema, Pydantic models, and reference implementations are publicly available on GitHub. Any tool can produce or consume CodeTF documents.
