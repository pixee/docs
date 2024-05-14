---
title: "Sonar: Add `abs_tol` to `math.isclose` Call"
sidebar_position: 1
---

## sonar:python/fix-math-isclose-S6727

| Importance | Review Guidance    | Requires Scanning Tool |
| ---------- | ------------------ | ---------------------- |
| Low        | Merge After Review | Yes (Sonar)            |

This codemod acts upon the following Sonar rules: python:S6727.

The default value for the `abs_tol` argument to a `math.isclose` call is `0`. Using this default when comparing a value against `0`, such as in `math.isclose(a, 0)` is equivalent to a strict equality check to `0`, which is not the intended use of the `math.isclose` function.

This codemod adds `abs_tol=1e-09` to any call to `math.isclose` with one of of the first arguments evaluating to `0` if `abs_tol` is not already specified. `1e-09` is a starting point for you to consider depending on your calculation needs.

Our changes look like the following:

```diff
+import math
+
 def foo(a):
-    return math.isclose(a, 0)
+    return math.isclose(a, 0, abs_tol=1e-09)
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Review?

This change makes your code more accurate but in some cases it may be necessary to adjust the `abs_tol` parameter value for your particular calculations.

## Codemod Settings

N/A

## References

- [https://docs.python.org/3/library/math.html#math.isclose](https://docs.python.org/3/library/math.html#math.isclose)
- [The abs_tol parameter should be provided when using math.isclose to compare values to 0](https://rules.sonarsource.com/python/RSPEC-6727/)
