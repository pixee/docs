---
title: Remove Unused Imports
sidebar_position: 1
---

## pixee:python/remove-unnecessary-f-str

| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
 | Low       | Merge Without Review | No                  |

Removes unused imports from a module. Imports involving the `__future__` module are ignored.

```diff
- import a 
import b

b.function()
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this codemod marked as Merge Without Review?

We believe this codemod is safe and will not cause any issues. It is important to note that importing modules may have side-effects that alter the behavior, even if unused, but we believe those cases are rare enough to be safe.

## Codemod Settings

N/A

## References
