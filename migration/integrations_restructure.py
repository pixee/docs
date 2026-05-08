#!/usr/bin/env python3
"""
Restructure the integrations section from a flat layout into two subcategories:
  /integrations/scms/<platform>     (GitHub, GitLab, Azure DevOps, Bitbucket)
  /integrations/scanners/<scanner>  (CodeQL, Semgrep, Snyk Code, ... 14 total)

ARCHIVED — committed for historical reference. NOT INTENDED TO BE RE-RUN.
This script captures the mechanical operations performed during the 2026-05-05
restructure. The new content authored alongside it (gitlab.md, azure-devops.md,
bitbucket.md, polaris.md, fortify.md, trivy.md, defectdojo.md, gitlab-sca.md)
was written by hand, not generated here.

Re-running would fail anyway: the source paths it expects (the old flat layout
with consolidated wrapper pages) no longer exist.

Working tree assumed at execution time:
    docs/                          (the pixee/docs repo root)
    └── docs/integrations/
        ├── codeql.md, semgrep.md, ...      (flat scanner pages)
        ├── github-platform.md              (flat SCM page)
        ├── commercial-scanners.md          (consolidated wrapper, deleted)
        ├── oss-aggregator-scanners.md      (consolidated wrapper, deleted)
        ├── scm-platform-reference.md       (consolidated wrapper, deleted)
        ├── integrations-overview.md
        └── sarif-universal.md

The script was placed at <root>/docs/migration/integrations_restructure.py and
run with `python3 migration/integrations_restructure.py`. It performed:

  1. mkdir docs/integrations/{scms,scanners}/
  2. git mv github-platform.md     -> scms/github.md
  3. git mv 9 scanner pages        -> scanners/<name>.md
  4. Update slugs to /integrations/scms/<x> and /integrations/scanners/<x>
  5. Update sidebar_position values (alphabetical within each subcategory)
  6. Rename github page title from "GitHub Platform Integration" to "GitHub Integration"
  7. Body-content link fixup: rewrite /integrations/<x> references to point at
     the new /integrations/scanners/<x> or /integrations/scms/<x> paths
  8. Delete the three consolidated wrappers (their content was extracted into
     individual scanner pages by hand)

Idempotent within its assumed layout. Each step is safe to re-run; the regex
substitutions are no-ops once applied.
"""

import pathlib
import re
import shutil
import subprocess

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
INTEGRATIONS = REPO_ROOT / "docs/integrations"

# (filename to move from flat layout, target subdir, new slug, sidebar_position, optional title rewrite)
SCANNER_MOVES = [
    ("appscan.md",     "scanners", "/integrations/scanners/appscan",     1,  None),
    ("checkmarx.md",   "scanners", "/integrations/scanners/checkmarx",   2,  None),
    ("codeql.md",      "scanners", "/integrations/scanners/codeql",      3,  None),
    ("contrast.md",    "scanners", "/integrations/scanners/contrast",    4,  None),
    # defectdojo, fortify, polaris, trivy, gitlab-sca authored fresh (positions 5, 6, 9, 14, 8)
    ("gitlab-sast.md", "scanners", "/integrations/scanners/gitlab-sast", 7,  None),
    ("semgrep.md",     "scanners", "/integrations/scanners/semgrep",     11, None),
    ("snyk-code.md",   "scanners", "/integrations/scanners/snyk-code",   12, None),
    ("sonarqube.md",   "scanners", "/integrations/scanners/sonarqube",   13, None),
    ("veracode.md",    "scanners", "/integrations/scanners/veracode",    15, None),
]

SCM_MOVES = [
    ("github-platform.md", "scms", "/integrations/scms/github", 3, "GitHub Integration"),
]
SCM_RENAMES = {"github-platform.md": "github.md"}  # rename on move

LINK_RULES = [
    # Removed wrappers → overview
    (r"\]\(/integrations/commercial-scanners(?=[)#])",     "](/integrations/overview"),
    (r"\]\(/integrations/oss-aggregator-scanners(?=[)#])", "](/integrations/overview"),
    (r"\]\(/integrations/scm-platforms(?=[)#])",           "](/integrations/overview"),
    # Flat scanner URLs → /scanners/ subfolder
    (r"\]\(/integrations/codeql(?=[)#])",      "](/integrations/scanners/codeql"),
    (r"\]\(/integrations/semgrep(?=[)#])",     "](/integrations/scanners/semgrep"),
    (r"\]\(/integrations/snyk-code(?=[)#])",   "](/integrations/scanners/snyk-code"),
    (r"\]\(/integrations/sonarqube(?=[)#])",   "](/integrations/scanners/sonarqube"),
    (r"\]\(/integrations/veracode(?=[)#])",    "](/integrations/scanners/veracode"),
    (r"\]\(/integrations/checkmarx(?=[)#])",   "](/integrations/scanners/checkmarx"),
    (r"\]\(/integrations/appscan(?=[)#])",     "](/integrations/scanners/appscan"),
    (r"\]\(/integrations/contrast(?=[)#])",    "](/integrations/scanners/contrast"),
    (r"\]\(/integrations/gitlab-sast(?=[)#])", "](/integrations/scanners/gitlab-sast"),
    # Flat SCM URL → /scms/ subfolder
    (r"\]\(/integrations/github(?=[)#])",      "](/integrations/scms/github"),
]

WRAPPER_FILES = [
    "commercial-scanners.md",
    "oss-aggregator-scanners.md",
    "scm-platform-reference.md",
]


def update_frontmatter(md_path: pathlib.Path, slug: str, position: int, new_title: str | None):
    text = md_path.read_text(encoding="utf-8")
    text = re.sub(r"^slug: .*$", f"slug: {slug}", text, count=1, flags=re.M)
    text = re.sub(r"^sidebar_position: .*$", f"sidebar_position: {position}", text, count=1, flags=re.M)
    if new_title:
        text = re.sub(r"^title: .*$", f"title: {new_title}", text, count=1, flags=re.M)
        text = re.sub(r"^# .*$", f"# {new_title}", text, count=1, flags=re.M)
    md_path.write_text(text, encoding="utf-8")


def move_files():
    (INTEGRATIONS / "scms").mkdir(exist_ok=True)
    (INTEGRATIONS / "scanners").mkdir(exist_ok=True)
    for filename, subdir, _, _, _ in SCANNER_MOVES + SCM_MOVES:
        src = INTEGRATIONS / filename
        dest_name = SCM_RENAMES.get(filename, filename)
        dest = INTEGRATIONS / subdir / dest_name
        if not src.exists():
            print(f"  skip (already moved or absent): {filename}")
            continue
        # Use git mv when possible; fall back to plain rename otherwise.
        try:
            subprocess.run(["git", "mv", str(src.relative_to(REPO_ROOT)), str(dest.relative_to(REPO_ROOT))],
                           cwd=REPO_ROOT, check=True, capture_output=True)
        except subprocess.CalledProcessError:
            shutil.move(str(src), str(dest))
        print(f"  moved {filename} -> {subdir}/{dest_name}")


def update_all_frontmatter():
    for filename, subdir, slug, position, new_title in SCANNER_MOVES + SCM_MOVES:
        dest_name = SCM_RENAMES.get(filename, filename)
        dest = INTEGRATIONS / subdir / dest_name
        if not dest.exists():
            print(f"  skip frontmatter (missing): {dest}")
            continue
        update_frontmatter(dest, slug, position, new_title)
        print(f"  frontmatter: {dest.name} slug={slug} pos={position}")


def fixup_body_links():
    docs_root = REPO_ROOT / "docs"
    compiled = [(re.compile(p), r) for p, r in LINK_RULES]
    total_subs = total_files = 0
    for md in docs_root.rglob("*.md"):
        text = md.read_text(encoding="utf-8")
        new_text = text
        file_subs = 0
        for pat, rep in compiled:
            new_text, n = pat.subn(rep, new_text)
            file_subs += n
        if new_text != text:
            md.write_text(new_text, encoding="utf-8")
            total_subs += file_subs
            total_files += 1
            print(f"  link fix: {md.relative_to(docs_root)} ({file_subs})")
    print(f"\n  {total_subs} link substitution(s) across {total_files} file(s)")


def remove_wrappers():
    for name in WRAPPER_FILES:
        target = INTEGRATIONS / name
        if not target.exists():
            print(f"  already removed: {name}")
            continue
        try:
            subprocess.run(["git", "rm", str(target.relative_to(REPO_ROOT))],
                           cwd=REPO_ROOT, check=True, capture_output=True)
        except subprocess.CalledProcessError:
            target.unlink()
        print(f"  removed: {name}")


def main():
    print("Step 1: move files")
    move_files()
    print("\nStep 2: update frontmatter")
    update_all_frontmatter()
    print("\nStep 3: body-content link fixup")
    fixup_body_links()
    print("\nStep 4: remove consolidated wrappers")
    remove_wrappers()
    print("\nDone.")


if __name__ == "__main__":
    main()
