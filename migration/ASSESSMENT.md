# docs.pixee.ai Migration — Assessment & Plan

**Date:** 2026-05-05
**Status:** Migration executed locally on branch `redesign/v2-content` (`pixee/docs`). Three commits ready to push. Build clean, all 72 pages return 200, redirects working. Awaiting push + PR.

---

## 1. The three repos and how they fit together

| Repo                                 | Role                                                                                                                                             |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `pixee-resources/Pixee-Marketing-OS` | Source of the **new** docs content (PR #117, merged 2026-04-28). Lives at `10_execute_short_term/pixee_docs/`.                                   |
| `pixee/docs`                         | Docusaurus 3.x **source** repo. Currently has ~9 thin pages. Migration PR target.                                                                |
| `pixee/internal-docs`                | **Deploy target only.** Every commit is `Deploy website - based on <sha>`. Serves `docs.pixee.ai` via GitHub Pages. We never edit this directly. |

**Deploy flow** (`pixee/docs/.github/workflows/deploy.yml`):

- PR to `pixee/docs#main` → `yarn build` runs as a check (test build only, no deploy).
- Push to `pixee/docs#main` → SSH-deploys via `yarn deploy` to `pixee/internal-docs#main`. That commit is what `docs.pixee.ai` serves.

`docusaurus.config.js` confirms: `organizationName: "pixee"`, `projectName: "internal-docs"`, `deploymentBranch: "main"`.

---

## 2. What's coming from PR #117

Lives at `Pixee-Marketing-OS/10_execute_short_term/pixee_docs/`:

- **71 markdown pages** in `pages/` across 10 sections: api (5), configuration (7), enterprise (11), faq (3), getting-started (8), how-it-works (6), integrations (14), languages (7), open-source (4), platform (6).
  - The handoff spec says 76; on-disk has 71. PR #117 did 13→4 consolidation in some folders. **Treat on-disk as truth.**
- Frontmatter is already Docusaurus-shaped: `title`, `slug`, `track` (`dev` | `leader` | `both`), `content_type`, `seo_title`, `meta_description`.
- Filenames are prefixed with a global ordinal (`01_…65_`). **Drop on copy.**
- No JSX/MDX in body content. Only `<…>` are inside code fences (Maven XML, csproj). Conversion is essentially a copy.

**Two data-quality issues the migration script must handle:**

1. **Track field case is inconsistent** — values include `dev`, `DEV`, `both`, `BOTH`, `leader`, `LEADER`, plus one stray `[leader, …]` array. Normalize to lowercase string.
2. **29 of 71 pages have duplicated frontmatter keys** (e.g., `title:` and `slug:` listed twice). Dedup, keeping the last occurrence (YAML parsers vary; Docusaurus accepts the last).

Companion artifacts in `pixee_docs/`:

- `site_architecture.md` — IA, sidebar mockup, URL structure
- `HANDOFF_SPEC.md` — implementation checklist
- `content_briefs/` — 76 per-page SEO briefs (we may extract some metadata from these later; not in v1 scope)
- `technical/` — `llms.txt`, `schema_specs.md`, `cross_domain_linking.md`, `entity_consistency.md`
- `gated_content/`, `quality_reviews/`, `extracts/`, `research_*` — out of scope for the docs migration.

---

## 3. What's there today (`pixee/docs`)

Total: ~9 pages, 729 lines. Auto-generated sidebar from filesystem.

```
docs/
├── intro.md
├── installing.md
├── faqs.md
├── languages.md
├── open-pixee.md
├── running_on_public_github_repos.md
├── supported-scms.md
├── using-pixeebot.md
└── code-scanning-tools/
    ├── overview.md
    ├── codeql.md
    ├── contrast.md
    ├── semgrep.md
    ├── snyk.md
    ├── sonar.md
    └── sonarqube.md
```

Existing redirects in `docusaurus.config.js`:

- `/integrations` → `/code-scanning-tools/overview`
- `/integrations/sonar` → `/code-scanning-tools/sonar`
- `/integrations/codeql` → `/code-scanning-tools/codeql`
- `/integrations/semgrep` → `/code-scanning-tools/semgrep`

These flip direction in v1: the new IA _is_ `/integrations/*`.

---

## 4. Decisions

| #   | Decision                                                                                                                                                                                                                                                                                      | Rationale                                                                                                                      |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| 1   | **Drop numeric filename prefixes.** Inject `sidebar_position` from prefix into frontmatter (renumbered dense per folder).                                                                                                                                                                     | Filenames are messy; ordering belongs in frontmatter.                                                                          |
| 2   | **Autogen sidebar.** No hand-built sidebar, no swizzle.                                                                                                                                                                                                                                       | User preference.                                                                                                               |
| 3   | **No track badges in the sidebar.** Originally we agreed to put `[DEV]/[LEADER]/[BOTH]` badges in `_category_.json` labels. Reverted after seeing it rendered — the badges read as visual noise. The `track:` field stays in frontmatter for potential v2 use (in-page audience pill).        | Cleaner sidebar; no information lost since users can still see context per page.                                               |
| 4   | **Skip the in-page "for: Developers" badge.**                                                                                                                                                                                                                                                 | Avoids swizzling theme components.                                                                                             |
| 5   | **Flatten Integrations** — drop the spec's `── Deep Integrations ── / ── Scanner Integrations ── / ── Platforms ──` sub-headers. All 14 integrations sit at the same level under `/integrations/`.                                                                                            | Sub-headers would require either a hand-built sidebar or splitting into subfolders (which would change URLs). Flat is cleaner. |
| 6   | **Skip React components for v1.** No `<AudienceBadge>`, no `<SchemaOrg>`, no `<FeedbackWidget>`. Defer to v2.                                                                                                                                                                                 | Trim scope.                                                                                                                    |
| 7   | **Include all config-file-level SEO improvements in v1.** See §6.                                                                                                                                                                                                                             | "Free" wins via headTags + static files + plugins.                                                                             |
| 8   | **Redirect every old URL** to its closest new equivalent. Preserve SEO regardless of traffic ranking.                                                                                                                                                                                         | With only 9 old pages, the redirect table is trivial; cost of being thorough is negligible.                                    |
| 9   | **Create `/integrations/contrast`** as part of the migration (the new IA needs a Contrast page; PR #117 didn't include one). Drafted from the existing 4-line `contrast.md` + public Contrast Security docs, matching the new docs voice (neutral, no marketing). David reviews before merge. | Contrast must exist in the new IA.                                                                                             |
| 10  | **One big PR** on `pixee/docs`, branch `redesign/v2-content`. Iterate locally.                                                                                                                                                                                                                | User preference.                                                                                                               |
| 11  | **Replace the React landing page with the welcome doc at `/`.** Deleted `src/pages/index.js` + `src/components/HomepageFeatures/`. Set `slug: /` on the welcome page so `docs.pixee.ai/` IS the welcome content (matches the spec).                                                           | Two competing landings (React hero + welcome doc) was confusing; the spec puts welcome at root.                                |

---

## 5. Redirect table

All old URLs → new equivalents. Implemented via `@docusaurus/plugin-client-redirects` (already installed).

| Old URL                           | New URL                       | Notes                                                          |
| --------------------------------- | ----------------------------- | -------------------------------------------------------------- |
| `/intro`                          | `/`                           | Welcome doc lives at root.                                     |
| `/installing`                     | `/`                           | Welcome page has platform tiles.                               |
| `/faqs`                           | `/faq/general`                | New IA splits FAQ into general / enterprise / troubleshooting. |
| `/languages`                      | `/languages/overview`         |                                                                |
| `/open-pixee`                     | `/open-source/overview`       |                                                                |
| `/running_on_public_github_repos` | `/configuration/repositories` | Verify on review — fallback `/getting-started/github`.         |
| `/supported-scms`                 | `/`                           | Welcome page lists all platforms with setup links.             |
| `/using-pixeebot`                 | `/getting-started/github`     | Pixeebot is the GitHub bot.                                    |
| `/getting-started`                | `/`                           | Welcome page promoted to root after Decision #11.              |
| `/code-scanning-tools/overview`   | `/integrations/overview`      |                                                                |
| `/code-scanning-tools/codeql`     | `/integrations/codeql`        |                                                                |
| `/code-scanning-tools/contrast`   | `/integrations/contrast`      | New page authored as part of this PR.                          |
| `/code-scanning-tools/semgrep`    | `/integrations/semgrep`       |                                                                |
| `/code-scanning-tools/snyk`       | `/integrations/snyk-code`     |                                                                |
| `/code-scanning-tools/sonar`      | `/integrations/sonarqube`     | Old IA had both `sonar` and `sonarqube` — collapsing.          |
| `/code-scanning-tools/sonarqube`  | `/integrations/sonarqube`     |                                                                |
| `/integrations`                   | `/integrations/overview`      | Was `→ /code-scanning-tools/overview`; flipped.                |
| `/integrations/sonar`             | `/integrations/sonarqube`     | Was `→ /code-scanning-tools/sonar`; updated.                   |

Total: 18 redirect rules. The pre-existing 4 redirects in `docusaurus.config.js` are repointed; everything else is net-new.

---

## 6. SEO additions in v1 (config-file-only) — DONE

All cheap, all React-free, all unblock AI crawlers and search engines. ~50 lines of config + 2 small static files. All five items below shipped.

| Item                                          | Where                                                             | Why                                                                                                      |
| --------------------------------------------- | ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| **Site-wide Organization JSON-LD** ✓          | `docusaurus.config.js` → `headTags`                               | Standard Org schema for Google AI Overviews / Bing Copilot.                                              |
| **`llms.txt` + `llms-full.txt`** ✓            | `docusaurus-plugin-llms@^0.4.0`                                   | Lets Claude / ChatGPT / Perplexity index the site cleanly. The handoff spec specifically calls this out. |
| **`robots.txt` allow-list for AI crawlers** ✓ | `static/robots.txt`                                               | Explicit allow for `GPTBot`, `ClaudeBot`, `PerplexityBot`, `Google-Extended`, etc.                       |
| **Sitemap** ✓                                 | Default in `@docusaurus/preset-classic`. Verified on new tree.    | Free.                                                                                                    |
| **Canonical URLs** ✓                          | Default Docusaurus behavior. `url` + `baseUrl` confirmed correct. | Free.                                                                                                    |

**Explicitly deferred to v2 (require components):**

- Per-page `FAQPage` JSON-LD (the spec's claimed 3.2x AI-Overview lift) → needs `<SchemaOrg>` component
- Per-page `HowTo` JSON-LD on setup pages → needs `<SchemaOrg>` component
- `<link rel="alternate" type="text/markdown">` to raw `.md` → needs swizzle
- `<AudienceBadge>` in-page rendering → needs swizzle
- `<FeedbackWidget>` thumbs-up/down → needs component + analytics endpoint
- Algolia DocSearch → defer; default search works
- HubSpot lead capture / gated content forms → out of scope for docs (marketing assets)

---

## 7. Migration plan — EXECUTED

**Branch:** `redesign/v2-content` on `pixee/docs`. Three commits ready to push:

```
f4a18e4 sidebar: drop track badges from category labels
7d97768 redesign: replace React landing with welcome page at root
4e3a5d5 redesign: replace docs with new IA from Pixee-Marketing-OS PR #117
```

PRs only run `yarn build` — no deploy until merge — so iteration is safe.

Phases below describe what was done.

### Phase A — Prep ✓

1. Branched off `pixee/docs#main`.
2. Deleted the existing `docs/*.md` and `docs/code-scanning-tools/`.

### Phase B — Content port ✓

A migration script (`migrate.py` at docswork root, ~150 lines, idempotent) walked `Pixee-Marketing-OS/10_execute_short_term/pixee_docs/pages/<section>/` and, for each `NN_<slug>.md`:

1. Reads frontmatter + body.
2. **Strips numeric prefix** from filename → `<slug>.md`.
3. **Dedups frontmatter keys** (last wins).
4. **Normalizes `track:`** to lowercase string (`dev` | `leader` | `both`).
5. **Injects `sidebar_position: <n>`** where `<n>` is the dense rank (1, 2, 3…) of the original prefix within the folder.
6. **Removes** non-Docusaurus frontmatter fields the spec carries that we don't use (`content_type`, `seo_title`, `meta_description` stay; we'll reuse them in v2 for schema).
7. Writes to `pixee/docs/docs/<section>/<slug>.md`.

For each section folder, the script writes a `_category_.json`:

```json
{
  "label": "Getting Started",
  "position": 1,
  "link": { "type": "doc", "id": "<section-overview-doc-id>" }
}
```

Section order and labels (track badges initially included, then dropped per Decision #3):

| #   | Folder             | Label               |
| --- | ------------------ | ------------------- |
| 1   | `getting-started/` | `Getting Started`   |
| 2   | `platform/`        | `Platform Overview` |
| 3   | `how-it-works/`    | `How It Works`      |
| 4   | `integrations/`    | `Integrations`      |
| 5   | `configuration/`   | `Configuration`     |
| 6   | `enterprise/`      | `Enterprise`        |
| 7   | `languages/`       | `Language Support`  |
| 8   | `api/`             | `API & Reference`   |
| 9   | `open-source/`     | `Open Source`       |
| 10  | `faq/`             | `FAQ`               |

### Phase C — Author the new Contrast page ✓

Drafted `docs/integrations/contrast.md` modeled on the new CodeQL/Semgrep page pattern (intro, "What Contrast Detects", "How Pixee Enhances Contrast" with Triage + Remediation, Setup, Common False Positive Patterns, FAQ). Source: existing 4-line `contrast.md` + public Contrast Security docs. Flagged in PR for David's review.

### Phase D — Config changes (`docusaurus.config.js`) ✓

1. Replaced the existing `redirects` array with the 18-entry table from §5.
2. Added Organization JSON-LD to `headTags`.
3. `yarn add docusaurus-plugin-llms@^0.4.0`, registered in `plugins[]` with default config.
4. Added `static/robots.txt` with AI-crawler allow-list.
5. Left navbar, footer, sitemap, GA / GTM as-is.

### Phase E — Build & link sanity ✓

1. Ran `yarn install` (picked up the new plugin).
2. Ran `yarn build` — surfaced 15 broken-link patterns (consolidated pages, IA renames, one missing `/demo` cross-domain link). Fixed via `fixup_links.py` (idempotent regex pass at docswork root) plus one manual edit. Re-built clean: 72 docs, zero broken links.
3. Ran `yarn serve` and curl-probed all 72 page slugs (all 200), all 10 category landings, JSON-LD on homepage, redirect targets, and sidebar order.

### Phase F — Homepage cleanup ✓

After initial verification, decided the React landing at `/` was redundant with the new welcome doc. Deleted `src/pages/index.js`, `src/pages/index.module.css`, `src/components/HomepageFeatures/`. Set `slug: /` on the welcome doc. Updated 5 internal `[](/getting-started)` references → `[](/)`. Added `/getting-started → /` redirect. Updated the three redirects that were targeting `/getting-started` (intro, installing, supported-scms) to target `/` instead.

### Phase G — Sidebar polish ✓

Initial implementation included `[DEV]`/`[LEADER]`/`[BOTH]` track badges in category labels per the original spec. After eyeballing in dev preview, reverted — labels now read as plain section names. The `track:` field is still present in page frontmatter for v2 use (in-page audience pill via swizzle).

### Phase H — Push + PR (next)

1. Push `redesign/v2-content` to `pixee/docs`. **(David runs locally; SSH agent.)**
2. Open PR. CI runs `yarn build` test only (no deploy).
3. Iterate via force-push as review feedback comes in.
4. Merge when ready → SSH deploy to `pixee/internal-docs` → live on `docs.pixee.ai`.

---

## 8. Risks / how each one resolved

1. **`onBrokenLinks: "throw"`** — landed: 15 broken-link patterns surfaced on first build, fixed via `fixup_links.py` (27 substitutions across 9 files) + one manual `/demo` → `pixee.ai/demo` edit. ✓
2. **Slug field consistency.** Every migrated page had an explicit `slug:` in frontmatter; all 72 slugs return 200. ✓
3. **Images / static assets.** No image references in the migrated body content. ✓
4. **Existing redirects flip direction.** Done — pre-existing 4 `/integrations/* → /code-scanning-tools/*` rules replaced. ✓
5. **Old integrations not in new IA.** Contrast handled (Decision #9). No other gaps identified. ✓
6. **Page count.** 71 (not the spec's 76). ✓ — reflected in commit message.

---

## 9. Out of scope for v1 (tracked for v2)

- React components: `<AudienceBadge>`, `<SchemaOrg>`, `<FeedbackWidget>`
- Per-page JSON-LD (FAQPage, HowTo, TechArticle, SoftwareApplication)
- Raw markdown alternates for AI agents (`.md` URL routes + `<link rel="alternate">`)
- Algolia DocSearch
- HubSpot lead capture, gated PDF downloads (the spec's 4 gated assets)
- GA4 custom events (scroll depth, code copy, CTA clicks)
- Cross-domain canonical / pixee.ai linking strategy from `cross_domain_linking.md`

---

## 10. Open items requiring human input before merge

- Verify `/configuration/repositories` is the right target for the `/running_on_public_github_repos` redirect. (Read the new page first; fall back to `/getting-started/github` if not the right fit.)
- David reviews the new `/integrations/contrast` page before merge.
- David eyeballs the deployed dev preview from the PR (or `yarn start` locally) and signals if anything reads off — sidebar order, integrations flat list, homepage content, redirects.

## 11. Tooling archived alongside this doc

This file lives at `migration/ASSESSMENT.md` in the `pixee/docs` repo, alongside:

- `migrate.py` — content port script that ran during the initial migration
- `fixup_links.py` — link-fixup pass that ran after `migrate.py`
- `README.md` — short orientation for anyone reading these files later

All three are checked in for historical reference. **Do not re-run them** — `migrate.py` would wipe manually-authored pages (e.g., `docs/integrations/contrast.md`) and ignore in-repo edits made after the migration commit (e.g., `slug: /` on the welcome doc). The scripts assumed a working tree containing both `Pixee-Marketing-OS/` and `docs/` as siblings; that layout no longer exists.
