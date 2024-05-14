---
title: "Replace == comparison with numpy.isnan()"
sidebar_position: 1
---

## pixee:python/numpy-nan-equality

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| Low        | Merge Without Review | No                     |

Comparisons against `numpy.nan` always result in `False`. Thus comparing an expression directly against `numpy.nan` is always unintended. The correct way to compare a value for `NaN` is to use the `numpy.isnan` function.

Our changes look something like this:

```diff
import numpy as np

a = np.nan
-if a == np.nan:
+if np.isnan(a):
    pass
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

We believe any use of `==` to compare with `numpy.nan` is unintended given that it is always `False`. Thus we consider this change safe.

## Codemod Settings

N/A

## References

- [https://numpy.org/doc/stable/reference/constants.html#numpy.nan](https://numpy.org/doc/stable/reference/constants.html#numpy.nan)
