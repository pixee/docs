---
title: Convert Eager Logging to Lazy Logging
sidebar_position: 1
---

## pixee:python/lazy-logging

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| Medium     | Merge Without Review | No                     |

This codemod converts "eager" logging into "lazy" logging, which is preferred for performance efficiency and resource optimization.
Lazy logging defers the actual construction and formatting of log messages until it's confirmed that the message will be logged based on the current log level, thereby avoiding unnecessary computation for messages that will not be logged. 

Our changes look something like this:

```diff
import logging
e = "Some error"
- logging.error("Error occurred: %s" % e)
- logging.error("Error occurred: " + e)
+ logging.error("Error occurred: %s", e)
+ logging.error("Error occurred: %s", e)
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

We believe this change is safe and will not cause any issues.

## Codemod Settings

N/A

## References

N/A
