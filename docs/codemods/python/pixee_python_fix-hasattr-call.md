---
title: "Use `callable` builtin to check for callables"
sidebar_position: 1
---

## pixee:python/fix-hasattr-call

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| Low        | Merge Without Review | No                     |

This codemod fixes cases where `hasattr` is used to check if an object is a callable. You likely want to use `callable` instead. This is because using `hasattr` will return different results in some cases, such as when the class implements a `__getattr__` method.

Our changes look something like this:

```diff
 class Test:
     pass

 obj = Test()
- hasattr(obj, "__call__")
+ callable(obj)
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

We believe this change is safe because using `callable` is a more reliable way to check if an object is a callable.

## Codemod Settings

N/A

## References

- [https://docs.python.org/3/library/functions.html#callable](https://docs.python.org/3/library/functions.html#callable)
- [https://docs.python.org/3/library/functions.html#hasattr](https://docs.python.org/3/library/functions.html#hasattr)
