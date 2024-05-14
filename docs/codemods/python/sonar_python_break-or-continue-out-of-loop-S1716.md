---
title: "Sonar: Removed break or continue statement out of loop"
sidebar_position: 1
---

## sonar:python/break-or-continue-out-of-loop-S1716

| Importance | Review Guidance    | Requires Scanning Tool |
| ---------- | ------------------ | ---------------------- |
| Low        | Merge After Review | Yes (Sonar)            |

This codemod acts upon the following Sonar rules: python:S1716.

Any `break` or `continue` statements that are not inside a `for` or `while` loop will result in a `SyntaxError`. This codemod will remove them.

Our changes look something like this:

```diff
def f():
     print('not in a loop')
-    break
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Review?

While this change will make the code consistent, it is likely that the `break` or `continue` statement is a symptom of an error in program logic.

## Codemod Settings

N/A

## References

- [https://pylint.readthedocs.io/en/stable/user_guide/messages/error/not-in-loop.html](https://pylint.readthedocs.io/en/stable/user_guide/messages/error/not-in-loop.html)
- ["break" and "continue" should not be used outside a loop](https://rules.sonarsource.com/python/RSPEC-1716/)
