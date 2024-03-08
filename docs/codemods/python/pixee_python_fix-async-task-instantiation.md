---
title: "Use High-Level `asyncio` API Functions to Create Tasks"
sidebar_position: 1
---

## pixee:python/fix-async-task-instantiation

| Importance | Review Guidance            | Requires Scanning Tool |
| ---------- | -------------------------- | ---------------------- |
| Low        | Merge After Cursory Review | No                     |

The `asyncio` [documentation](https://docs.python.org/3/library/asyncio-task.html#asyncio.Task) explicitly discourages manual instantiation of a `Task` instance and instead recommends calling `create_task`. This keeps your code in line with recommended best practices and promotes maintainability.

Our changes look like the following:

```diff
 import asyncio

- task = asyncio.Task(my_coroutine(), name="my task")
+ task = asyncio.create_task(my_coroutine(), name="my task")
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

Manual instantiation of `asyncio.Task` is discouraged. We believe this change is safe and will not cause any issues.

## Codemod Settings

N/A

## References

- [https://docs.python.org/3/library/asyncio-task.html#asyncio.Task](https://docs.python.org/3/library/asyncio-task.html#asyncio.Task)
