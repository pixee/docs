---
title: "Use Set Literals Instead of Sets from Lists"
sidebar_position: 1
---

## pixee:python/use-set-literal

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| Low        | Merge Without Review | No                     |

This codemod converts Python set constructions using literal list arguments into more efficient and readable set literals. It simplifies expressions like `set([1, 2, 3])` to `{1, 2, 3}`, enhancing both performance and code clarity.

Our changes look like this:

```diff
-x = set([1, 2, 3])
+x = {1, 2, 3}
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

We believe this change is safe and will not cause any issues.

## Codemod Settings

N/A

## References

N/A
