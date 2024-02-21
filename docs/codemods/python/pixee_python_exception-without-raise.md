---
title: "Ensure bare exception statements are raised"
sidebar_position: 1
---

## pixee:python/exception-without-raise

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| Low        | Merge Without Review | No                     |

This codemod fixes cases where an exception is referenced by itself in a statement without being raised. This most likely indicates a bug: you probably meant to actually raise the exception. 

Our changes look something like this:
```diff
try:
-   ValueError
+   raise ValueError
except:
    pass
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

A statement with an exception by itself has no effect. Raising the exception is most likely the intended effect and thus we deem it safe.

## Codemod Settings

N/A

## References

* [https://docs.python.org/3/tutorial/errors.html#raising-exceptions](https://docs.python.org/3/tutorial/errors.html#raising-exceptions)
