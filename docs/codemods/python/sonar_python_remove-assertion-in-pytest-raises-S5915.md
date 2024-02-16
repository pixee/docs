---
title: Sonar: Moves assertions out of `pytest.raises` scope
sidebar_position: 1
---

## sonar:python/remove-assertion-in-pytest-raises-S5915

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| Low        | Merge Without Review | Yes (Sonar)            |

This codemod acts upon the following Sonar rules: 'python:S5915'.

The context manager object `pytest.raises(<exception>)` will assert if the code contained within its scope will raise an exception of type `<exception>`. The documentation points that the exception must be raised in the last line of its scope and any line afterwards won't be executed. 
Including asserts at the end of the scope is a common error. This codemod addresses that by moving them out of the scope.
Our changes look something like this:

```diff
import pytest

def test_foo():
    with pytest.raises(ZeroDivisionError):
        error = 1/0
-       assert 1
-       assert 2
+   assert 1
+   assert 2
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

We believe this change is safe and will not cause any issues.

## Codemod Settings

N/A

## References

* [https://docs.pytest.org/en/7.4.x/reference/reference.html#pytest-raises](https://docs.pytest.org/en/7.4.x/reference/reference.html#pytest-raises)
* [https://rules.sonarsource.com/python/type/Bug/RSPEC-5915/](https://rules.sonarsource.com/python/type/Bug/RSPEC-5915/)
