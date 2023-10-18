---
title: Separate Lock Instantiation from `with` Call
sidebar_position: 1
---

## pixee:python/bad-lock-with-statement

| Importance | Review Guidance            | Requires SARIF Tool |
|------------|----------------------------|---------------------|
| Low       | Merge Without Review | No                  |

This codemod separates creating a threading lock instance from calling it as a context manager.
Calling `with threading.Lock()` does not have the effect you would expect. The lock is not acquired.
Instead, to correctly acquire a lock, create the instance separately, before calling it as a context manager.

The change will apply to any of these `threading` classes: `Lock`, `RLock`, `Condition`, `Semaphore`, and `BoundedSemaphore`.

The change looks like this:

```diff
  import threading
- with threading.Lock():
+ lock = threading.Lock()
+ with lock:
     ...
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

We believe this replacement is safe and should not result in any issues.

## Codemod Settings

N/A

## References

* [https://pylint.pycqa.org/en/latest/user_guide/messages/warning/useless-with-lock.](https://pylint.pycqa.org/en/latest/user_guide/messages/warning/useless-with-lock.)
* [https://docs.python.org/3/library/threading.html#using-locks-conditions-and-semaphores-in-the-with-statement](https://docs.python.org/3/library/threading.html#using-locks-conditions-and-semaphores-in-the-with-statement)
