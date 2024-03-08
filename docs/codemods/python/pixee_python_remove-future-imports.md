---
title: "Remove deprecated `__future__` imports"
sidebar_position: 1
---

## pixee:python/remove-future-imports

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| Low        | Merge Without Review | No                     |

Many older codebases have `__future__` imports for forwards compatibility with features. As of this writing, all but one of those features is now stable in all currently supported versions of Python and so the imports are no longer needed. While such imports are harmless, they are also unnecessary and in most cases you probably just forgot to remove them.

This codemod removes all such `__future__` imports, preserving only those that are still necessary for forwards compatibility.

Our changes look like the following:

```diff
 import os
-from __future__ import print_function

 print("HELLO")
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

Removing future imports is safe and will not cause any issues.

## Codemod Settings

N/A

## References

- [https://docs.python.org/3/library/**future**.html](https://docs.python.org/3/library/__future__.html)
