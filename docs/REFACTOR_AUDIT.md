# Pixee Docs Refactor Audit

## Stats

- **Current page count:** 75 .md files (excluding `migration/`)
- **Estimated total word count:** ~86,000 words
- **Pages with embedded FAQ sections:** 72 of 75 pages contain a `## Frequently Asked Questions` or `## FAQ` section appended at the end

### Pages WITH embedded FAQ sections (72 of 75)

Every page except the three standalone FAQ pages (`faq/faq-general.md`, `faq/faq-enterprise.md`, `faq/faq-troubleshooting.md`) has an embedded FAQ section. This includes:

**getting-started/ (7 pages):** getting-started.md, github.md, gitlab.md, azure-devops.md, bitbucket.md, ci-cd.md, cli.md, first-fix.md

**how-it-works/ (6 pages):** triage-engine.md, fix-generation.md, fix-safety.md, sca-pipeline.md, scanner-integration.md, context-intelligence.md

**platform/ (6 pages):** what-is-agentic-security-engineering.md, architecture.md, triage.md, remediation.md, sca.md, security.md

**configuration/ (6 pages):** config-overview.md, pixee-yaml.md, repositories.md, operations-config.md, users.md, ai-settings.md

**enterprise/ (11 pages):** enterprise-overview.md, deployment.md, embedded-cluster.md, helm.md, air-gap.md, compliance.md, security-architecture.md, byom.md, observability.md, phased-rollout.md, troubleshooting.md

**integrations/ (19 pages):** integrations-overview.md, sarif-universal.md, all 11 scanner pages, all 4 SCM pages

**languages/ (7 pages):** languages-overview.md, java.md, python.md, javascript.md, dotnet.md, go.md, php.md

**open-source/ (4 pages):** oss-overview.md, codemodder.md, custom-codemods.md, contributing.md

**api/ (4 pages):** api-overview.md, sarif.md, webhooks.md, changelog.md

---

## IA Evaluation

### What Works

1. **Integrations pages are properly scoped.** Each of the 13 scanner pages and 4 SCM pages covers a distinct integration. These are genuinely separate entities and the per-page structure is correct.

2. **Configuration section is well-organized.** The three-level hierarchy (PIXEE.yaml → org settings → AI settings) is clearly communicated and each page has a distinct subject.

3. **Enterprise section covers real sub-topics.** Deployment, air-gap, BYOM, observability, compliance, security-architecture, phased-rollout, and troubleshooting each address distinct subjects that justify separate pages at Tier 2 depth.

4. **Language pages are correctly scoped.** One page per language with framework coverage, fix types, and examples. The languages-overview coverage matrix is a useful landing page.

5. **Getting-started SCM setup pages are appropriately differentiated.** GitHub, GitLab, ADO, and Bitbucket each have platform-specific credential requirements, permission scopes, and terminology (PR vs MR) that justify separate pages.

6. **The changelog.md is the only page with actual changelog content and no duplication problem.** It contains real versioned entries and is appropriately a reference page.

### What Doesn't Work

1. **The `how-it-works/` and `platform/` sections cover nearly identical ground, split arbitrarily by stated audience.** The `track` field distinguishes them (leader vs both), but the content overlap is severe enough that readers arriving at one section must also read the other to get the full picture.

2. **72 of 75 pages end with an embedded FAQ section.** These sections overwhelmingly restate content already covered earlier in the same page. They add length without adding value and create duplication relative to the three dedicated FAQ pages.

3. **The three dedicated FAQ pages (`faq/`) are thin and mostly redirect to other pages** rather than actually answering questions. `faq-enterprise.md` is almost entirely stub answers saying "See [page X]." This renders the section nearly useless.

4. **Scanner count is inconsistent across the docs.** The integrations overview and several pages claim 13 named scanners (correct per the matrix: CodeQL, Semgrep, Checkmarx, Veracode, Snyk Code, SonarQube, AppScan, Polaris, Fortify, Contrast, GitLab SAST, GitLab SCA, Trivy + DefectDojo as aggregator). But ~26 other pages still say "12 native integrations." The changelog shows Arnica SAST was added in v5.4.11 and Datadog SAST in v5.4.15, and neither is fully reflected in the scanner pages. This is a live inconsistency.

5. **The learning loop is almost entirely undocumented.** Marketing claims Pixee "learns from merge/reject/comment feedback over time." The only mention in the entire docs is one sentence in `platform/triage.md`: "When Pixee classifies a finding as FALSE_POSITIVE but your team disagrees, the override is recorded and used to improve future classifications for your codebase." No page explains how this learning actually works, at what scope (repo, org, global), on what cadence, or with what effect.

6. **Dashboard and reporting capabilities are scattered.** `configuration/operations-config.md` has a Reporting section. `enterprise/enterprise-overview.md` has a Measuring Success section. `platform/architecture.md` mentions the React frontend but barely explains what it shows. There is no dedicated dashboard or reporting page despite the dashboard being a primary interface for security leads.

7. **The `getting-started/` section has a structural gap.** `getting-started.md` (root) explains the platform well. The four SCM setup pages are good. But `ci-cd.md` and `cli.md` are more advanced topics that belong in a different section or clearly labeled as advanced/optional. They inflate the perceived complexity of "getting started."

### Section Overlap: how-it-works vs platform

#### Findings

The two sections cover the same four core topics with significant content redundancy:

| Topic | platform/ page | how-it-works/ page | Overlap assessment |
|---|---|---|---|
| Triage | `platform/triage.md` (1,444 words) | `how-it-works/triage-engine.md` (1,906 words) | ~70% content overlap. Both explain three-tier architecture, tier-by-tier breakdown, structured verdicts, context signals, scanner-agnostic coverage. `how-it-works` adds a tier comparison table and "Triage and Remediation: Closing the Loop" section. `platform/triage` adds the scanner list and a slightly different intro framing. |
| Fix generation | `platform/remediation.md` (1,201 words) | `how-it-works/fix-generation.md` (1,719 words) | ~65% overlap. Both cover deterministic vs AI, fix evaluation rubric, multi-agent planning, PR delivery. `how-it-works` adds context gathering detail and 4-tier dataflow classification. |
| SCA | `platform/sca.md` (1,137 words) | `how-it-works/sca-pipeline.md` (1,240 words) | ~60% overlap. Both cover exploitability verification, transitive dependencies, atomic PRs, multi-manifest support. `how-it-works` adds verification cache and cross-tool intelligence sections. |
| Fix safety/trust | `platform/security.md` (1,883 words) | `how-it-works/fix-safety.md` (1,586 words) | ~55% overlap. Both cover deterministic vs AI safety, independent evaluation, PR-only workflow, 76% merge rate. `platform/security` adds data handling, deployment models, and "Responsible AI Council" framing. |

Additionally, `how-it-works/scanner-integration.md` and `how-it-works/context-intelligence.md` have no direct `platform/` counterpart, but `platform/architecture.md` summarizes both.

The stated rationale (platform/ is for leaders, how-it-works/ is for engineers) does not hold in practice. The content in each pair is too similar to serve genuinely different audiences without significant rewriting.

#### Proposed Resolution

**PROPOSED:** Consolidate into a single section. Eliminate `platform/` as a separate section. Rewrite each topic as one authoritative page at Tier 2 depth (thorough, depth-friendly). The business/leadership framing that currently lives in `platform/` can be integrated into the opening paragraphs and callout boxes rather than requiring separate pages.

Specific merges:
- Merge `platform/triage.md` + `how-it-works/triage-engine.md` → single `how-it-works/triage.md`
- Merge `platform/remediation.md` + `how-it-works/fix-generation.md` → single `how-it-works/fix-generation.md`
- Merge `platform/sca.md` + `how-it-works/sca-pipeline.md` → single `how-it-works/sca.md`
- Merge `platform/security.md` + `how-it-works/fix-safety.md` → single `how-it-works/fix-safety.md`
- Keep `platform/architecture.md` as an overview/landing page for the section (rename section to `how-it-works/`)
- Keep `platform/what-is-agentic-security-engineering.md` — move it to become the section landing page or merge into the main overview

### Other Structural Issues

1. **`faq/` section is structurally incoherent.** Three files exist: general, enterprise, troubleshooting. But `faq-enterprise.md` consists almost entirely of answers that say "See [page X]." It is a stub masquerading as content. `faq-troubleshooting.md` has genuinely useful step-by-step troubleshooting content. `faq-general.md` is substantive but repeats content from `how-it-works/` and `platform/`. **PROPOSED:** Remove `faq-enterprise.md` (all its questions are answered on the linked pages). Promote `faq-troubleshooting.md` content into a dedicated Troubleshooting section. Keep `faq-general.md` as a navigation/discovery page only, ruthlessly cutting answers that duplicate canonical pages.

2. **`open-source/` section has four pages but the last three are thin.** `codemodder.md` and `oss-overview.md` cover similar ground. `contributing.md` is too short to be a standalone page. `custom-codemods.md` is a tutorial that should either live in a tutorials section or be merged with `codemodder.md`. **PROPOSED:** Merge `oss-overview.md` + `codemodder.md` → one reference page. Merge `custom-codemods.md` as a tutorial subsection. Fold `contributing.md` content into the merged page as a short section.

3. **`api/` section is incomplete.** `api-overview.md` has authentication details and placeholder endpoint descriptions. `api/sarif.md` largely duplicates `integrations/sarif-universal.md`. `changelog.md` is the only page with real content. The API docs lack actual endpoint reference (request/response schemas). This section promises Tier 3 reference content but delivers Tier 2 overviews.

4. **`getting-started/ci-cd.md` is misplaced.** It is a configuration/integration guide, not a getting-started page. New users do not need CI/CD pipeline examples to evaluate Pixee. **PROPOSED:** Move `ci-cd.md` to `integrations/` or `configuration/`.

5. **`getting-started/cli.md` is misplaced.** The CLI is an advanced operational tool, not part of the initial setup path. The getting-started root explicitly states "No CLI required for the standard workflow." **PROPOSED:** Move `cli.md` to the `api/` section or create a dedicated `tools/` section.

---

## Proposed IA Changes

All items below are PROPOSED. None are implemented.

| # | Proposal | Rationale |
|---|---|---|
| 1 | Consolidate `platform/triage.md` + `how-it-works/triage-engine.md` into one page | ~70% content overlap; same topic, same depth, different words |
| 2 | Consolidate `platform/remediation.md` + `how-it-works/fix-generation.md` into one page | ~65% content overlap |
| 3 | Consolidate `platform/sca.md` + `how-it-works/sca-pipeline.md` into one page | ~60% content overlap |
| 4 | Consolidate `platform/security.md` + `how-it-works/fix-safety.md` into one page | ~55% content overlap; trust framing can be a section, not a whole parallel page |
| 5 | Remove `faq/faq-enterprise.md` | Every answer is a redirect stub. All content exists on linked pages. |
| 6 | Move `faq-troubleshooting.md` content to a dedicated Troubleshooting section or integrate with `enterprise/troubleshooting.md` | Troubleshooting content is genuinely useful but misplaced in FAQ structure |
| 7 | Move `getting-started/ci-cd.md` to `integrations/` | CI/CD integration is not a getting-started topic |
| 8 | Move `getting-started/cli.md` to `api/` or `tools/` | CLI is an advanced operational tool, explicitly not required for standard workflow |
| 9 | Merge `open-source/oss-overview.md` + `open-source/codemodder.md` | Two pages covering same ground (what codemods are, the framework, the repos) |
| 10 | Remove embedded FAQ sections from all 72 pages | 72 pages have appended FAQ sections that restate the page content. Convert at most 2-3 per page into callout boxes where the Q&A adds genuinely new framing not in the body text. |
| 11 | Add a dedicated Learning Loop page | Core differentiator (Pixee improves from feedback) is essentially undocumented |
| 12 | Add a dedicated Dashboard & Reporting page | Reporting metrics are scattered across 4+ pages with no canonical home |
| 13 | Fix scanner count inconsistency across all pages (12 vs 13 vs current actual) | Changelog shows Arnica and Datadog SAST added; integrations overview shows 13 + DefectDojo; most pages still say 12 |
| 14 | Reconcile `api/sarif.md` with `integrations/sarif-universal.md` | Same SARIF format reference material in two places; one should link to the other |

---

## Per-Section Tier Assignments

| Section | Pages | Tier | Notes |
|---|---|---|---|
| `getting-started/getting-started.md` | 1 | Tier 1 | Landing page; currently well-scoped but has padding in the FAQ section |
| `getting-started/` SCM setup (github, gitlab, azure-devops, bitbucket) | 4 | Tier 1 | Setup pages; currently about right in length but each has an embedded FAQ that restates the setup steps |
| `getting-started/first-fix.md` | 1 | Tier 1 | Good candidate for aggressive tightening; currently repeats PR anatomy twice |
| `getting-started/ci-cd.md` | 1 | Tier 2 | Misplaced — should move to integrations/; content depth is appropriate for Tier 2 |
| `getting-started/cli.md` | 1 | Tier 2 | Misplaced — should move to api/ or tools/; content depth is appropriate for Tier 2 |
| `how-it-works/triage-engine.md` | 1 | Tier 2 | Appropriate depth; consolidation target |
| `how-it-works/fix-generation.md` | 1 | Tier 2 | Appropriate depth; consolidation target |
| `how-it-works/fix-safety.md` | 1 | Tier 2 | Appropriate depth; consolidation target |
| `how-it-works/sca-pipeline.md` | 1 | Tier 2 | Appropriate depth; consolidation target |
| `how-it-works/scanner-integration.md` | 1 | Tier 2 | Good standalone page with real technical detail |
| `how-it-works/context-intelligence.md` | 1 | Tier 2 | Solid but partially duplicated by triage-engine.md's "Context-Aware Intelligence" section |
| `platform/` (all 6 pages) | 6 | Tier 2 | Section should be eliminated/merged into how-it-works; content is appropriate Tier 2 depth but redundant |
| `configuration/pixee-yaml.md` | 1 | Tier 3 | Full schema reference; appropriate |
| `configuration/operations-config.md` | 1 | Tier 2 | Mixed content (scheduling, notifications, reporting) — may need splitting |
| `configuration/` (remaining) | 4 | Tier 2 | Appropriate depth |
| `enterprise/deployment.md` | 1 | Tier 2 | Good depth; some overlap with embedded-cluster.md and helm.md |
| `enterprise/embedded-cluster.md` | 1 | Tier 2 | Appropriate |
| `enterprise/helm.md` | 1 | Tier 2 | Appropriate |
| `enterprise/air-gap.md` | 1 | Tier 2 | Appropriate |
| `enterprise/security-architecture.md` | 1 | Tier 2 | Appropriate; partially overlaps platform/security.md |
| `enterprise/compliance.md` | 1 | Tier 2-3 | Framework mapping table is Tier 3; surrounding prose is Tier 2 |
| `enterprise/byom.md` | 1 | Tier 2 | Appropriate |
| `enterprise/observability.md` | 1 | Tier 2 | Appropriate |
| `enterprise/phased-rollout.md` | 1 | Tier 2 | Appropriate |
| `enterprise/troubleshooting.md` | 1 | Tier 3 | Reference troubleshooting tables; appropriate |
| `enterprise/enterprise-overview.md` | 1 | Tier 1 | Landing page; currently has too much detail (Measuring Success section should move to operations-config) |
| `integrations/integrations-overview.md` | 1 | Tier 2 | Coverage matrix is Tier 3; page is appropriate |
| `integrations/sarif-universal.md` | 1 | Tier 2-3 | SARIF field requirements lean Tier 3 |
| `integrations/scanners/` (13 pages) | 13 | Tier 2 | Each scanner page has appropriate depth for its audience |
| `integrations/scms/` (4 pages) | 4 | Tier 2 | Credential tables and permission scopes are appropriately detailed |
| `languages/languages-overview.md` | 1 | Tier 2 | Coverage matrix is Tier 3; combined makes this right |
| `languages/java.md`, `languages/python.md` | 2 | Tier 2 | Appropriate depth |
| `languages/javascript.md`, `languages/dotnet.md`, `languages/go.md`, `languages/php.md` | 4 | Tier 2 | Currently thinner than Java/Python pages; acceptable given less coverage |
| `faq/faq-general.md` | 1 | Tier 1 | Navigation/discovery; cut answers that duplicate canonical pages |
| `faq/faq-enterprise.md` | 1 | — | PROPOSED REMOVAL: all answers are redirect stubs |
| `faq/faq-troubleshooting.md` | 1 | Tier 2 | Good operational content; should be promoted to a real Troubleshooting section |
| `open-source/oss-overview.md` | 1 | Tier 1 | Landing page; overlaps too much with codemodder.md |
| `open-source/codemodder.md` | 1 | Tier 2 | Appropriate depth; consolidation target with oss-overview |
| `open-source/custom-codemods.md` | 1 | Tier 2 | Tutorial; could be merged into codemodder.md as a section |
| `open-source/contributing.md` | 1 | Tier 1 | Too short standalone; should be a section of codemodder.md |
| `api/api-overview.md` | 1 | Tier 3 | Promises reference content but is currently Tier 2 depth; needs expansion |
| `api/sarif.md` | 1 | Tier 3 | Duplicates integrations/sarif-universal.md; needs consolidation |
| `api/webhooks.md` | 1 | Tier 3 | Appropriate |
| `api/changelog.md` | 1 | Tier 3 | Appropriate; only page with no real content problem |

---

## Top 10 Pages Needing Most Work

Ranked by severity of problem and fix urgency:

### 1. `platform/triage.md` — MERGE
**Problem:** Covers nearly identical ground as `how-it-works/triage-engine.md`. Both pages open with a full description of the three-tier architecture, walk through each tier, describe the structured verdict format, and list the same four context signals. The platform page adds a scanner list table that belongs on the triage page. The how-it-works page adds a tier comparison table and a closing "Triage and Remediation" section. Combined, there are 3,350 words covering one topic.  
**Action:** Merge into a single definitive triage page. Start with the three-tier architecture overview, add the tier comparison table, include the context signals section, end with structured verdicts. Target: 1,600–1,800 words. Delete the platform version.

### 2. `platform/remediation.md` — MERGE
**Problem:** Covers nearly identical ground as `how-it-works/fix-generation.md`. Both pages explain the deterministic/AI routing decision, the fix quality evaluation rubric (Safety/Effectiveness/Cleanliness), and multi-agent fix planning. The platform page has a language coverage table; the how-it-works page has the 4-tier dataflow context gathering table and MagicMod architecture details. Combined: 2,920 words, one topic.  
**Action:** Merge into a single authoritative fix generation page. Preserve the dataflow context gathering table (it adds real value). Target: 1,800–2,000 words.

### 3. `platform/security.md` + `how-it-works/fix-safety.md` — MERGE/REWRITE
**Problem:** Both pages are long (1,883 and 1,586 words) and cover the same three concepts: deterministic vs AI, independent evaluation, PR-only workflow. `platform/security.md` adds data handling and the Responsible AI Council framing; these are worth keeping. Combined there are 3,469 words of largely redundant content.  
**Action:** Merge into one "Security & Trust" page. Keep the Responsible AI Council Q&A (it addresses a real evaluation concern). Keep the data handling section. Eliminate the repeated fix quality rubric (covered on the merged fix generation page). Target: 1,500–1,800 words.

### 4. Embedded FAQ sections on 72 pages — STRIP GLOBALLY
**Problem:** Every content page ends with a `## Frequently Asked Questions` or `## FAQ` section that largely restates the page body. Examples: `platform/triage.md` FAQ asks "How does automated vulnerability triage reduce false positives?" — a question answered in the preceding 1,200 words. `how-it-works/fix-generation.md` FAQ asks "What is the difference between codemods and AI-generated fixes?" — answered with a full table earlier on the same page. These sections add 100–400 words to every page, inflating total word count by an estimated 15,000–20,000 words across the site.  
**Action:** Strip embedded FAQ sections from all 72 pages. Where a question genuinely covers something not in the page body (rare), convert it to a callout box or inline summary. Do not route to the standalone FAQ pages; those should also be cut or consolidated.

### 5. `faq/faq-enterprise.md` — REMOVE
**Problem:** Every answer in this page is a redirect to another page. Example: "Does Pixee support self-hosted deployment? See [Deployment Options](/enterprise/deployment) for details." This is not an FAQ — it is an index, and a worse index than the sidebar. The page adds zero content.  
**Action:** Remove the page. Redirect the slug to `/enterprise/overview`.

### 6. `how-it-works/context-intelligence.md` — MERGE OR DEMOTE
**Problem:** This page covers four topics (dataflow quality, production vs test, security control detection, intentionally-vulnerable project filtering) that are already summarized in `how-it-works/triage-engine.md`'s "Context-Aware Intelligence" section, which contains a table covering the same four-tier dataflow scale. The context-intelligence page adds slightly more prose but no new concepts. It then has a "How Context Feeds Remediation" section that duplicates `how-it-works/fix-generation.md`'s context gathering section.  
**Action:** After the triage + fix generation merges, assess whether this page still has unique content. If the merged triage page covers the four context signals adequately, fold the unique parts of context-intelligence.md into the merged triage page and delete this page.

### 7. `platform/what-is-agentic-security-engineering.md` — REPURPOSE OR MERGE
**Problem:** This page (the conceptual explainer for what "agentic" means) is positioned as a `platform/` page but reads like a landing page or marketing overview. After the platform/how-it-works consolidation, its role is unclear. Its "Four-Layer Security Stack" table is genuinely useful. The "What Makes It Agentic" section is good framing but exists nowhere in the consolidated architecture.  
**Action:** Move this page to become the section landing page (replacing the current `platform/architecture.md` overview function) with a new slug like `/how-it-works/` or `/platform/overview`. Trim the embedded FAQ. Keep the four-layer table and the "agentic" definition section.

### 8. `api/api-overview.md` — EXPAND
**Problem:** This page promises a REST API reference but delivers only authentication setup and a brief mention that endpoints exist. There are no actual endpoint definitions, request/response schemas, or error response examples. The `api/` section claims to be Tier 3 reference content but is currently Tier 2 at best.  
**Action:** Expand the API overview to include all available endpoints with method, path, parameters, and response shape. If the full reference lives elsewhere (e.g., an OpenAPI spec), link to it prominently. Currently a user asking "how do I query my scan results via API?" gets no actionable answer from this page.

### 9. `configuration/operations-config.md` — SPLIT OR RESTRUCTURE
**Problem:** This page covers three distinct operational areas — scheduling, notifications, and reporting — in a single 2,900-word page. The reporting section describes dashboard metrics (triage summary, fix activity, merge rate, remediation velocity) that have no other home. The scheduling section overlaps with what `configuration/config-overview.md` says about workflows. The notifications section is well-written but buries the Jira/ServiceNow webhook configuration at the end.  
**Action:** Consider splitting into two pages: `operations-scheduling.md` (scheduling + notifications) and `reporting.md` (dashboard + metrics + exports + compliance exports). This would give reporting a canonical home and reduce the page's sprawl.

### 10. Learning loop — CREATE
**Problem:** One of Pixee's three core differentiators ("Learn — improves from merge/reject/comment feedback over time") has no documentation. The only reference in the entire docs is a single sentence in `platform/triage.md`: "When Pixee classifies a finding as FALSE_POSITIVE but your team disagrees, the override is recorded and used to improve future classifications for your codebase." This cannot verify whether Pixee learns globally, per-org, per-repo, on what signal (overrides only, or also merge/reject?), at what cadence, or with measurable effect.  
**Action:** Create a new page (suggested: `how-it-works/learning.md`) covering: what signals Pixee ingests (triage overrides, PR merges, PR closes, code comments), the scope of learning (org-level? global?), the cadence and mechanism, and how teams can evaluate whether learning is improving accuracy over time. This page cannot be written without consulting product/engineering to verify what actually ships.

---

## Cross-Page Duplication

### 1. Three-tier triage architecture description
**Repeated on:** `platform/triage.md`, `how-it-works/triage-engine.md`, `platform/architecture.md`, `platform/what-is-agentic-security-engineering.md`, `getting-started/getting-started.md`, `faq/faq-general.md`  
**Proposed canonical location:** `how-it-works/triage.md` (post-merge). All others should summarize in 1-2 sentences and link.

### 2. Fix quality evaluation rubric (Safety/Effectiveness/Cleanliness)
**Repeated on:** `platform/remediation.md`, `how-it-works/fix-generation.md`, `how-it-works/fix-safety.md`, `platform/security.md`, `faq/faq-general.md`, `getting-started/first-fix.md`, `getting-started/github.md`, `getting-started/gitlab.md`, `getting-started/azure-devops.md`, `getting-started/bitbucket.md`  
**Proposed canonical location:** `how-it-works/fix-generation.md` (post-merge). PR description sections on SCM setup pages should say "quality scores (Safety, Effectiveness, Cleanliness)" with a link.

### 3. "Deterministic codemods vs AI-powered MagicMods" explanation
**Repeated on:** `platform/remediation.md`, `how-it-works/fix-generation.md`, `how-it-works/fix-safety.md`, `platform/security.md`, `platform/what-is-agentic-security-engineering.md`, `configuration/ai-settings.md`, `faq/faq-general.md`, `getting-started/first-fix.md`  
**Proposed canonical location:** `how-it-works/fix-generation.md`. Other pages should use: "Pixee uses deterministic codemods for known patterns and AI-powered MagicMods for novel ones — [see Fix Generation]."

### 4. PR-only delivery as architectural constraint
**Repeated on:** `platform/remediation.md`, `how-it-works/fix-safety.md`, `platform/security.md`, `platform/architecture.md`, `platform/what-is-agentic-security-engineering.md`, `enterprise/security-architecture.md`, `faq/faq-general.md`, `getting-started/getting-started.md`  
**Proposed canonical location:** `how-it-works/fix-safety.md` (post-merge with security.md). One sentence + link on all other pages.

### 5. Deployment model comparison (Cloud SaaS / Embedded Cluster / Helm / Air-Gapped)
**Repeated on:** `enterprise/deployment.md`, `enterprise/enterprise-overview.md`, `enterprise/security-architecture.md`, `getting-started/` SCM setup pages (data-leaves-your-network section), `getting-started/ci-cd.md`  
**Proposed canonical location:** `enterprise/deployment.md`. All others should show only the deployment model names and link.

### 6. "No CLI required / no code changes to install"
**Repeated on:** `getting-started/getting-started.md`, `getting-started/github.md`, `getting-started/gitlab.md`, `getting-started/azure-devops.md`, `getting-started/bitbucket.md`, `faq/faq-general.md`  
**Proposed canonical location:** `getting-started/getting-started.md`. SCM setup pages can keep one sentence of confirmation but do not need full paragraphs.

### 7. "git revert applies; no runtime dependency on Pixee for merged code"
**Repeated on:** `platform/remediation.md`, `how-it-works/fix-safety.md`, `platform/security.md`, `platform/architecture.md`, `faq/faq-general.md`  
**Proposed canonical location:** `how-it-works/fix-safety.md`. Two sentences on other pages maximum.

### 8. 76% merge rate claim
**Repeated on:** `platform/remediation.md`, `how-it-works/fix-safety.md`, `platform/security.md`, `getting-started/getting-started.md`, and 4+ other pages  
**Proposed canonical location:** `how-it-works/fix-safety.md` with the full context. Other pages should say "76% merge rate — see [Fix Safety]" without re-explaining what the number means.

### 9. Infrastructure requirements (8 vCPU, 32 GB RAM, 100 GB SSD)
**Repeated on:** `enterprise/deployment.md`, `enterprise/embedded-cluster.md`, `enterprise/helm.md`, `enterprise/air-gap.md`, `faq/faq-enterprise.md`  
**Proposed canonical location:** `enterprise/deployment.md` (already has the definitive table). Other pages should link to it, not repeat it.

### 10. Scanner count ("12 native integrations") — currently an inconsistency
**Repeated incorrectly on:** ~26 pages saying "12" while integrations-overview.md correctly shows 13 named scanners (Arnica SAST and Datadog SAST added per changelog). The actual count, including DefectDojo as an aggregator, is 14 supported scanners, 13 named as "native."  
**Proposed canonical location:** `integrations/integrations-overview.md` has the definitive matrix. All other pages should say "13 named scanner integrations" and link. Requires auditing the exact current list (Arnica, Datadog per changelog; both pages are missing from `integrations/scanners/`).

---

## Content Gaps

### 1. The Learning Loop — CRITICAL GAP
**What's missing:** How Pixee improves from feedback. This is described as a core product capability but has zero dedicated documentation. The single sentence ("overrides are recorded and used to improve future classifications") does not explain mechanism, scope, cadence, or measurability.  
**Where it should live:** `how-it-works/learning.md` (new page)  
**What it should cover:** Signal types (overrides, PR merges, PR closes, inline comments), scope (per-repo vs org vs global model improvement), cadence (immediate? batch? weekly?), how teams can observe improvement over time, any measurable effect on false positive rates.  
**Blocker:** Requires product/engineering input to document accurately. Cannot be written from existing docs alone.

### 2. Dashboard and Reporting Interface — SIGNIFICANT GAP
**What's missing:** The Pixee dashboard is mentioned everywhere as the primary interface for security leads, but it is never shown or described in detail. What does it look like? What views exist? How are findings organized? What filtering is available? What does the triage summary view show?  
**Where it should live:** `configuration/operations-config.md` Reporting section (currently exists but only describes metrics in abstract — no screenshots, no view descriptions, no navigation guidance)  
**What it should cover:** Primary dashboard views (triage summary, fix activity, repository status), filtering controls, how to read merge rate and MTTR metrics, how to export data.

### 3. Convention-Aware Fix Generation — SIGNIFICANT GAP
**What's missing:** Marketing copy says Pixee generates "context-aware code fixes matching team conventions." The PIXEE.yaml page documents the `pr` section (labels, reviewers, draft) but this is PR metadata, not fix conventions. The `fix-generation.md` page mentions "per-project PIXEE.yaml policy" for preferred imports and framework choices but `pixee-yaml.md` has no corresponding schema fields for coding conventions, preferred imports, or framework preferences. Either the PIXEE.yaml schema is incomplete in the docs, or the convention-awareness is an AI behavior not user-configurable.  
**Where it should live:** `configuration/pixee-yaml.md` and `how-it-works/fix-generation.md`  
**What it should cover:** What aspects of team conventions Pixee detects automatically vs. what requires explicit configuration, what PIXEE.yaml fields (if any) control fix style.

### 4. Triage Verdict Override Workflow — MODERATE GAP
**What's missing:** Multiple pages mention that security engineers can override triage verdicts. None explain how to do this. Where in the UI? What happens when you override? Is there a comment field? Does the override affect future findings? Is it per-finding or per-rule?  
**Where it should live:** `how-it-works/triage.md` (post-merge) — add a "Overriding Triage Verdicts" section  
**What it should cover:** UI/API mechanics for overrides, the scope of an override, how overrides feed into learning.

### 5. Arnica SAST and Datadog SAST Integration Pages — MISSING
**What's missing:** The changelog (v5.4.11 and v5.4.15) shows Arnica SAST and Datadog SAST were added as native integrations. The integrations-overview.md doesn't list them. There are no scanner pages for either in `integrations/scanners/`. The platform/triage.md lists them in the scanner list but there is no integration setup page.  
**Where it should live:** `integrations/scanners/arnica.md` and `integrations/scanners/datadog-sast.md` (new pages)

### 6. Multi-Scanner Deduplication — MODERATE GAP
**What's missing:** `platform/triage.md` mentions "cross-tool deduplication -- when multiple scanners flag the same finding, the system eliminates duplicates." This is a real operational question for teams running 3-4 scanners. How does deduplication work? What defines a "duplicate"? When does Pixee merge findings vs. treat them independently?  
**Where it should live:** `how-it-works/scanner-integration.md` or the merged triage page

### 7. SCA Verification Cache Details — MINOR GAP
**What's missing:** `how-it-works/sca-pipeline.md` mentions a "verification cache" for CVE+dependency combinations. What is the TTL? Is it per-org or global? How does it interact with new CVE advisories for the same library version?  
**Where it should live:** `how-it-works/sca.md` (post-merge)

### 8. Phased Rollout Success Metrics — MODERATE GAP
**What's missing:** `enterprise/phased-rollout.md` describes phases but the Phase 1 success criteria section (seen in first 50 lines) is cut off in this audit. More importantly, there is no guidance on how to set up measurement during a rollout — specifically, how to access merge rate data, triage volume data, and developer acceptance metrics during the pilot phase before org-wide deployment.  
**Where it should live:** `enterprise/phased-rollout.md` + link to the Reporting section

---

## Flags for Human Review

1. **Scanner count accuracy.** The actual current number of supported scanners needs verification. The integrations-overview claims 13 named + DefectDojo as aggregator. The changelog mentions Arnica (v5.4.11) and Datadog SAST (v5.4.15). But neither appears in `integrations/scanners/` as a page. Many older pages say "12." What is the current authoritative count, and which scanners have dedicated setup pages vs. just changelog mentions?

2. **85% SCA noise reduction and 90% less triage time claims** on `platform/sca.md`. These are presented as product claims without qualification (unlike the 95% triage claim, which includes a detailed qualification about workload composition). Are these numbers validated? If so, they need the same qualification treatment. If not, they should be removed.

3. **Learning loop — product reality.** Before writing any documentation about the learning loop, engineering must confirm: (a) Does Pixee actually improve triage accuracy from feedback signals in a live, deployed way? (b) What signals does it ingest? (c) Is improvement per-repo, per-org, or global? (d) Is this a shipped feature or a roadmap item? The current docs imply it exists ("overrides are recorded and used to improve") but do not validate this.

4. **PIXEE.yaml convention fields.** The `fix-generation.md` page says "Per-project PIXEE.yaml policy. MagicMods respect project-level configuration files specifying your coding conventions, preferred imports, and framework choices." But `pixee-yaml.md` has no schema fields for preferred imports or framework choices. Either (a) these PIXEE.yaml fields exist but are undocumented, (b) the convention-awareness is automatic (detected, not configured), or (c) this is planned, not shipped. This needs engineering clarification before the docs can be corrected.

5. **"50+ validated" SARIF scanners.** Multiple pages claim "over 50 scanner tools have been validated via the universal SARIF path." Is there a public list? If not, this claim should be qualified as "50+ scanners in Pixee's testing environment" rather than implying any scanner producing SARIF is guaranteed to work.

6. **Air-gapped deployment license validation.** `enterprise/air-gap.md` says "License validation still requires a network path to Pixee servers — either direct or through a proxy." This is called out as "An honest clarification" in the page. Given that many air-gapped use cases are in environments where NO outbound internet is allowed (classified DoD environments, for example), this limitation may be a deal-stopper that the docs currently undersell. Flag for product decision: is there a fully offline license model, and if so, how does it work?

7. **`platform/what-is-agentic-security-engineering.md` — audience and SEO intent.** This page is positioned as a conceptual explainer for search traffic ("What is agentic security engineering?") but currently lives deep in the `platform/` section. If this page is intended to capture search traffic from users who don't know Pixee, it should be the highest-level page in the site or live at the root. If it's for existing users, it can live in the platform section. The intent needs clarification before IA is finalized.

8. **`api/changelog.md` has a FAQ section.** The changelog's embedded FAQ includes "How often does Pixee release updates?" (answered: ~25 releases per 6 months). This is the most recent and specific product frequency information in the docs and should inform the enterprise-overview.md's similar claim (currently consistent). However, the changelog FAQ is the only place this appears. Verify that the "25 releases in 6 months" figure is current.

9. **`enterprise/troubleshooting.md` vs. `faq/faq-troubleshooting.md` overlap.** Both cover troubleshooting but for different audiences: enterprise-troubleshooting covers Helm/K8s/LLM issues; faq-troubleshooting covers scanner connectivity and PR issues. After consolidation, ensure the separation remains clean and cross-links are correct.

10. **`configuration/operations-config.md` references `configuration/operations`** in the config-overview quick reference table. This slug does not match the actual slug `configuration/operations` — the file is `operations-config.md` with slug `/configuration/operations`. Verify all internal links are correct after any consolidation.
