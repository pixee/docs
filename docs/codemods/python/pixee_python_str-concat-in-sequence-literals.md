---
title: "Convert Implicit String Concat Inside Sequence into Individual Elements"
sidebar_position: 1
---

## pixee:python/str-concat-in-sequence-literals

| Importance | Review Guidance            | Requires Scanning Tool |
|------------|----------------------------|------------------------|
| Medium     | Merge After Cursory Review | No                     |

This codemod fixes cases of implicit string concatenation inside lists, sets, or tuples. This is most likely a mistake: you probably meant include a comma in between the concatenated strings. 

Our changes look something like this:
```diff
bad = [
-    "ab"
+    "ab",
     "cd",
     "ef",
-    "gh"
+    "gh",
     "ij",
]
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

While string concatenation inside a sequence iterable is likely a mistake, there are instances when you may choose to use them..

## Codemod Settings

N/A

## References

N/A
