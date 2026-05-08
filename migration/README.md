# Migration archive

These files document the 2026-05-05 docs redesign — replacing the previous ~9-page site with the 71-page IA from `Pixee-Marketing-OS` PR #117.

## Contents

| File                          | What it is                                                                                                                                                                                                           |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ASSESSMENT.md`               | The planning + decision-log document. Captures the three-repo deploy flow, decisions made, redirect table, SEO additions, and what was actually executed.                                                            |
| `migrate.py`                  | One-shot Python script that ported content from `Pixee-Marketing-OS/10_execute_short_term/pixee_docs/pages/` into `docs/docs/`. Normalized frontmatter, dropped numeric prefixes, generated `_category_.json` files. |
| `fixup_links.py`              | One-shot Python script that fixed 27 internal markdown links across 9 files (consolidated/renamed pages, IA renames).                                                                                                |
| `integrations_restructure.py` | Follow-up restructure that split flat `/integrations/<x>` into `/integrations/scms/<x>` and `/integrations/scanners/<x>`. Captures the moves, frontmatter updates, body-link fixup, and wrapper-file deletions.      |

## Do not re-run the scripts

These are committed for historical reference, not as a re-runnable pipeline.

- `migrate.py` is destructive: it wipes `docs/docs/` and rewrites everything from `Pixee-Marketing-OS/`. Re-running it would delete `docs/integrations/contrast.md` (manually authored) and revert the welcome doc's `slug: /` (set after migration).
- The scripts also assume a sibling working-tree layout (`Pixee-Marketing-OS/` next to `docs/`) that no longer exists.
- For future content updates, edit `docs/` directly. `Pixee-Marketing-OS` is no longer the source of truth for these docs.

## Why keep them

Future-you (or future-someone) will eventually ask:

- _Why is the file numbering weird?_ — Because `pages/` files used `NN_<slug>.md` for global ordering; we kept the order in `sidebar_position` instead.
- _Why is there a Contrast page that doesn't match the format of the others?_ — Because PR #117 dropped Contrast from the IA; we re-added it.
- _Why does the redirect table have so many rules?_ — The old `/code-scanning-tools/*` IA was inverted to `/integrations/*`.
- _Why is `track:` in frontmatter if nothing renders it?_ — Reserved for a v2 audience-badge component.

`ASSESSMENT.md` answers all of those.
