---
title: "Sonar: Replace `is` with `==` for literal or new object comparisons"
sidebar_position: 1
---

## sonar:python/literal-or-new-object-identity-S5796

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| Low        | Merge Without Review | Yes (Sonar)            |

This codemod acts upon the following Sonar rules: python:S5796.

The `is` and `is not` operators only evaluate to `True` when the expressions on each side have the same `id`. In other words, `a is b` is equivalent to `id(a) == id(b)`. With few exceptions, objects and literals have unique identities and thus shouldn't generally be compared by using the `is` or `is not` operators.

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

- [https://docs.python.org/3/library/stdtypes.html#comparisons](https://docs.python.org/3/library/stdtypes.html#comparisons)
- [New objects should not be created only to check their identity](https://rules.sonarsource.com/python/type/Bug/RSPEC-5796/)
