---
title: "Simplify Boolean Expressions Using `isinstance` and `issubclass`"
sidebar_position: 1
---

## pixee:python/combine-isinstance-issubclass

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| Low        | Merge Without Review | No                     |

Many developers are not necessarily aware that the `isinstance` and `issubclass` builtin methods can accept a tuple of classes to match. This means that there is a lot of code that uses boolean expressions such as `isinstance(x, str) or isinstance(x, bytes)` instead of the simpler expression `isinstance(x, (str, bytes))`.

This codemod simplifies the boolean expressions where possible which leads to cleaner and more concise code.

The changes from this codemod look like this:

```diff
  x = 'foo'
- if isinstance(x, str) or isinstance(x, bytes):
+ if isinstance(x, (str, bytes)):
     ...
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

Simplifying expressions involving `isinstance` or `issubclass` calls is safe.

## Codemod Settings

N/A

## References

N/A
