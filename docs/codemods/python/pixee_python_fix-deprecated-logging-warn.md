---
title: "Replace Deprecated `logging.warn`"
sidebar_position: 1
---

## pixee:python/fix-deprecated-logging-warn

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| Low        | Merge Without Review | No                     |

The `warn` method from `logging` has been [deprecated](https://docs.python.org/3/library/logging.html#logging.Logger.warning) in favor of `warning` since Python 3.3. Since the old method `warn` has been retained for a long time, there are a lot of developers that are unaware of this change and consequently a lot of code using the older method.

Our changes look like the following:

```diff
 import logging

- logging.warn("hello")
+ logging.warning("hello")
 ...
 log = logging.getLogger("my logger")
- log.warn("hello")
+ log.warning("hello")
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

This change fixes deprecated uses and is safe.

## Codemod Settings

N/A

## References

- [https://docs.python.org/3/library/logging.html#logging.Logger.warning](https://docs.python.org/3/library/logging.html#logging.Logger.warning)
