---
title: "Sonar: Fix `assert` on Non-Empty Tuple Literal"
sidebar_position: 1
---

## sonar:python/fix-assert-tuple-S5905

| Importance | Review Guidance            | Requires Scanning Tool |
|------------|----------------------------|------------------------|
| Medium     | Merge After Cursory Review | Yes (Sonar)            |

This codemod acts upon the following Sonar rules: 'python:S5905'.

An assertion on a non-empty tuple will always evaluate to `True`. This means that `assert` statements involving non-empty tuple literals are likely unintentional and should be rewritten. This codemod rewrites the original `assert` statement by creating a new `assert` for each item in the original tuple.

The changes from this codemod look like this:

```diff
- assert (1 == 1, 2 == 2)
+ assert 1 == 1
+ assert 2 == 2
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

An `assert` statement on a non-empty tuple is likely unintended and should be rewritten. However, the new change may result in assertion failures that should be reviewed.

## Codemod Settings

N/A

## References

* [https://rules.sonarsource.com/python/type/Bug/RSPEC-5905/](https://rules.sonarsource.com/python/type/Bug/RSPEC-5905/)