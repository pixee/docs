#!/usr/bin/env python3
"""
Fix internal links in the migrated docs that reference pages consolidated/renamed
in PR #117 but still appear in body content.

ARCHIVED — committed for historical reference. NOT INTENDED TO BE RE-RUN.
Re-running is safe (regex no-ops if patterns already replaced), but the link
shape has since drifted (e.g., /getting-started → /). See README.md.

Originally placed at <root>/fixup_links.py alongside migrate.py and run after it.
Idempotent: each rule is a regex that becomes a no-op once applied.
"""

import pathlib
import re

DOCS = pathlib.Path(__file__).parent / "docs/docs"

# Each rule is a (regex, replacement). Patterns target markdown link bodies
# `](URL)` and `](URL#anchor)` to avoid matching the same path elsewhere.
# Order matters: prefix-matched rules must come before their parent prefixes.
RULES = [
    # Configuration: notifications + reporting were folded into operations.md
    (r"\]\(/configuration/notifications(?=[)#])", "](/configuration/operations"),
    (r"\]\(/configuration/reporting(?=[)#])",     "](/configuration/operations"),

    # Integrations: individual scanner pages folded into bundles
    (r"\]\(/integrations/defectdojo(?=[)#])", "](/integrations/oss-aggregator-scanners"),
    (r"\]\(/integrations/trivy(?=[)#])",      "](/integrations/oss-aggregator-scanners"),
    (r"\]\(/integrations/fortify(?=[)#])",    "](/integrations/commercial-scanners"),
    (r"\]\(/integrations/polaris(?=[)#])",    "](/integrations/commercial-scanners"),

    # SCM platforms: gitlab/azure/bitbucket folded into scm-platforms
    (r"\]\(/integrations/azure-devops(?=[)#])", "](/integrations/scm-platforms"),
    (r"\]\(/integrations/bitbucket(?=[)#])",    "](/integrations/scm-platforms"),
    (r"\]\(/integrations/gitlab(?=[)#])",       "](/integrations/scm-platforms"),

    # SARIF naming
    (r"\]\(/integrations/sarif(?=[)#])",            "](/integrations/sarif-universal"),
    (r"\]\(/integrations/universal-sarif(?=[)#])",  "](/integrations/sarif-universal"),

    # Section overview links that dropped the /overview suffix
    (r"\]\(/integrations(?=[)#])", "](/integrations/overview"),
    (r"\]\(/languages(?=[)#])",    "](/languages/overview"),

    # Typos / wrong sections
    (r"\]\(/enterprise/deployment-options(?=[)#])",   "](/enterprise/deployment"),
    (r"\]\(/getting-started/phased-rollout(?=[)#])",  "](/enterprise/phased-rollout"),
]

COMPILED = [(re.compile(p), r) for p, r in RULES]


def main():
    total_changes = 0
    files_changed = 0
    for md in DOCS.rglob("*.md"):
        text = md.read_text(encoding="utf-8")
        original = text
        file_changes = 0
        for pat, rep in COMPILED:
            new_text, n = pat.subn(rep, text)
            file_changes += n
            text = new_text
        if text != original:
            md.write_text(text, encoding="utf-8")
            total_changes += file_changes
            files_changed += 1
            print(f"  {md.relative_to(DOCS)}: {file_changes} fix(es)")
    print(f"\n{total_changes} link fix(es) across {files_changed} file(s)")


if __name__ == "__main__":
    main()
