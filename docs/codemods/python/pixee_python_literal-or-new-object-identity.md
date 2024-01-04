---
title: Replaces is operator with == for literal or new object comparisons
sidebar_position: 1
---

## pixee:python/literal-or-new-object-identity

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| Low        | Merge Without Review | No                     |

The `is` and `is not` operator will only return `True` when the expression have the same `id`. In other words, `a is b` is equivalent to `id(a) == id(b)`. New objects and literals have their own identities and thus shouldn't be compared with using the `is` or `is not` operators.

Our changes look something like this:

```diff
def foo(l):
-    return l is [1,2,3]
+    return l == [1,2,3]
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

Since literals and new objects have their own identities, comparisons against them using `is` operators are most likely a bug and thus we deem the change safe.

## Codemod Settings

N/A

## References

* [https://docs.python.org/3/library/stdtypes.html#comparisons](https://docs.python.org/3/library/stdtypes.html#comparisons)
