#!/usr/bin/env python3
"""
Migrate PR #117 content from Pixee-Marketing-OS into pixee/docs.

ARCHIVED — committed for historical reference. NOT INTENDED TO BE RE-RUN.
Re-running would wipe manually-authored pages (e.g., docs/integrations/contrast.md)
and ignore later in-repo edits like the slug change on the welcome doc. See README.md.

Working tree assumed at execution time:
    <root>/
    ├── Pixee-Marketing-OS/10_execute_short_term/pixee_docs/pages/<section>/NN_<slug>.md
    └── docs/docs/<section>/<slug>.md   (target, this repo)

The script was placed at <root>/migrate.py and run with `python3 migrate.py`.

Behavior: walks every section, drops numeric filename prefixes, dedups frontmatter
keys (last wins), normalizes `track:` to lowercase, injects sidebar_position,
renames meta_description -> description, writes _category_.json per section.
Idempotent within its assumed layout: always rewrites the target tree from scratch.
"""

import json
import pathlib
import re
import shutil
import sys

ROOT = pathlib.Path(__file__).parent.resolve()
SRC = ROOT / "Pixee-Marketing-OS/10_execute_short_term/pixee_docs/pages"
DST = ROOT / "docs/docs"

# (folder, sidebar label, position, link spec)
# link spec: ("doc", "<doc-id>") | ("generated-index", None)
CATEGORIES = [
    ("getting-started", "Getting Started",   1, ("doc", "getting-started/getting-started")),
    ("platform",        "Platform Overview", 2, ("doc", "platform/what-is-agentic-security-engineering")),
    ("how-it-works",    "How It Works",      3, ("generated-index", None)),
    ("integrations",    "Integrations",      4, ("doc", "integrations/integrations-overview")),
    ("configuration",   "Configuration",     5, ("doc", "configuration/config-overview")),
    ("enterprise",      "Enterprise",        6, ("doc", "enterprise/enterprise-overview")),
    ("languages",       "Language Support",  7, ("doc", "languages/languages-overview")),
    ("api",             "API & Reference",   8, ("doc", "api/api-overview")),
    ("open-source",     "Open Source",       9, ("doc", "open-source/oss-overview")),
    ("faq",             "FAQ",              10, ("doc", "faq/faq-general")),
]

# Frontmatter fields we keep (and rename if needed). All other unknown keys are kept verbatim.
RENAME = {"meta_description": "description"}

PREFIX_RE = re.compile(r"^(\d+)_(.+\.md)$")
FM_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$")


def parse_frontmatter(text: str):
    """Return (ordered list of (key, value) pairs with last-wins dedup, body)."""
    if not text.startswith("---\n") and not text.startswith("---\r\n"):
        return [], text
    # Locate closing ---
    lines = text.splitlines(keepends=True)
    end_idx = None
    for i in range(1, len(lines)):
        if lines[i].rstrip() == "---":
            end_idx = i
            break
    if end_idx is None:
        return [], text
    fm_lines = lines[1:end_idx]
    body = "".join(lines[end_idx + 1:]).lstrip("\n")

    # Build ordered dict with last-wins dedup.
    pairs = []
    seen = {}
    for raw in fm_lines:
        m = FM_LINE_RE.match(raw.rstrip("\n"))
        if not m:
            # Skip blank/comment lines silently. We don't expect nested YAML structures
            # in this content set (verified manually); flag if assumption breaks.
            if raw.strip() and not raw.lstrip().startswith("#"):
                print(f"  WARN: unparseable frontmatter line: {raw!r}", file=sys.stderr)
            continue
        key, val = m.group(1), m.group(2).strip()
        # Strip surrounding quotes (single or double).
        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
        if key in seen:
            pairs[seen[key]] = (key, val)  # last wins
        else:
            seen[key] = len(pairs)
            pairs.append((key, val))
    return pairs, body


def normalize_track(val: str) -> str:
    """Normalize track values like 'DEV', 'BOTH', '[leader, both]' to a lowercase string."""
    v = val.strip().strip("[]")
    # Take first item if comma-separated (e.g., "leader, both")
    v = v.split(",")[0].strip().strip("'\"")
    return v.lower()


def serialize_frontmatter(pairs) -> str:
    """Emit a YAML frontmatter block. Quote any value that needs quoting."""
    out = ["---"]
    for k, v in pairs:
        sv = str(v)
        # Quote if value contains YAML-special chars or starts with whitespace.
        needs_quote = (
            sv == "" or
            any(c in sv for c in [':', '#', '|', '>', '"', "'", '*', '&', '!']) or
            sv != sv.strip()
        )
        if isinstance(v, int):
            out.append(f"{k}: {v}")
        elif needs_quote:
            out.append(f"{k}: {json.dumps(sv)}")
        else:
            out.append(f"{k}: {sv}")
    out.append("---")
    return "\n".join(out)


def migrate_section(section: str, label: str, position: int, link_spec):
    src_dir = SRC / section
    dst_dir = DST / section
    if dst_dir.exists():
        shutil.rmtree(dst_dir)
    dst_dir.mkdir(parents=True, exist_ok=True)

    files = []
    for p in src_dir.glob("*.md"):
        m = PREFIX_RE.match(p.name)
        if not m:
            print(f"  WARN: no numeric prefix on {p.name}, skipping", file=sys.stderr)
            continue
        files.append((int(m.group(1)), m.group(2), p))
    files.sort()

    for sidebar_pos, (orig_n, slug_name, src_file) in enumerate(files, start=1):
        text = src_file.read_text(encoding="utf-8")
        pairs, body = parse_frontmatter(text)

        # Normalize / rename / inject.
        normalized = []
        for k, v in pairs:
            if k == "track":
                v = normalize_track(v)
            new_k = RENAME.get(k, k)
            normalized.append((new_k, v))

        # Inject sidebar_position (replace if already present).
        for i, (k, _) in enumerate(normalized):
            if k == "sidebar_position":
                normalized[i] = ("sidebar_position", sidebar_pos)
                break
        else:
            normalized.append(("sidebar_position", sidebar_pos))

        out_text = serialize_frontmatter(normalized) + "\n\n" + body
        (dst_dir / slug_name).write_text(out_text, encoding="utf-8")

    # _category_.json
    cat = {"label": label, "position": position, "collapsible": True, "collapsed": False}
    if link_spec[0] == "doc":
        cat["link"] = {"type": "doc", "id": link_spec[1]}
    elif link_spec[0] == "generated-index":
        cat["link"] = {"type": "generated-index"}
    (dst_dir / "_category_.json").write_text(json.dumps(cat, indent=2) + "\n", encoding="utf-8")

    print(f"  {section}: {len(files)} pages")


def main():
    if not SRC.exists():
        sys.exit(f"Source not found: {SRC}")
    if not DST.parent.exists():
        sys.exit(f"Target docs repo not found: {DST.parent}")

    # Wipe everything under docs/docs/ first so we start clean.
    if DST.exists():
        shutil.rmtree(DST)
    DST.mkdir(parents=True, exist_ok=True)

    print("Migrating sections:")
    for section, label, position, link_spec in CATEGORIES:
        migrate_section(section, label, position, link_spec)

    print(f"\nDone. Wrote to {DST}")


if __name__ == "__main__":
    main()
