---
title: Use Assignment Expression (Walrus) In Conditional
sidebar_position: 1
---

## pixee:python/use-walrus-if

| Importance | Review Guidance            | Requires Scanning Tool |
|------------|----------------------------|------------------------|
| Low        | Merge After Cursory Review | No                     |

This codemod updates places where two separate statements involving an assignment and conditional can be replaced with a single Assignment Expression (commonly known as the walrus operator).

Many developers use this operator in new code that they write but don't have the time to find and update every place in existing code. So we do it for you! We believe this leads to more concise and readable code.

The changes from this codemod look like this:

```diff
- x = foo()
- if x is not None:
+ if (x := foo()) is not None:
      print(x)
```

The walrus operator is only supported in Python 3.8 and later.

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

We believe that using the walrus operator is an improvement in terms of clarity and readability. However, this change is only compatible with codebases that support Python 3.8 and later, so it requires quick validation before merging.

## Codemod Settings

N/A

## References

* [https://docs.python.org/3/whatsnew/3.8.html#assignment-expressions](https://docs.python.org/3/whatsnew/3.8.html#assignment-expressions)
