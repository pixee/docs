---
title: Upgrade and Secure Temp File Creation
sidebar_position: 1
---

## pixee:python/secure-tempfile

| Importance | Review Guidance            | Requires SARIF Tool |
|------------|----------------------------|---------------------|
| High       | Merge Without Review | No                  |

This codemod replaces all `tempfile.mktemp` calls to the more secure `tempfile.mkstemp`.

The Python [tempfile documentation](https://docs.python.org/3/library/tempfile.html#tempfile.mktemp) is explicit
that `tempfile.mktemp` should be deprecated to avoid an unsafe and unexpected race condition.
The changes from this codemod look like this:


```diff
  import tempfile
- tempfile.mktemp(...)
+ tempfile.mkstemp(...)
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

We believe this codemod is safe and will cause no unexpected errors.

## Codemod Settings

N/A

## References

* [https://docs.python.org/3/library/tempfile.html#tempfile.mktemp](https://docs.python.org/3/library/tempfile.html#tempfile.mktemp)
