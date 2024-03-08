---
title: "Replace Comparisons to Empty Sequence with Implicit Boolean Comparison"
sidebar_position: 1
---

## pixee:python/fix-empty-sequence-comparison

| Importance | Review Guidance    | Requires Scanning Tool |
| ---------- | ------------------ | ---------------------- |
| Low        | Merge After Review | No                     |

Empty sequences in Python always evaluate to `False`. This means that comparison expressions that use empty sequences can sometimes be simplified. In these cases no explicit comparison is required: instead we can rely on the [truth value](https://docs.python.org/3/library/stdtypes.html#truth-value-testing) of the object under comparison. This is sometimes referred to as "implicit" comparison. Using implicit boolean comparison expressions is considered best practice and can lead to better code.

Our changes look like the following:

```diff
 x = [1]

- if x != []:
+ if x:
    pass
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Review?

Values compared to empty sequences should be verified in case they are falsy values that are not a sequence.

## Codemod Settings

N/A

## References

- [https://docs.python.org/3/library/stdtypes.html#truth-value-testing](https://docs.python.org/3/library/stdtypes.html#truth-value-testing)
