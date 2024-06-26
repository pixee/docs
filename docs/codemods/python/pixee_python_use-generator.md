---
title: "Use Generator Expressions Instead of List Comprehensions"
sidebar_position: 1
---

## pixee:python/use-generator

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| Low        | Merge Without Review | No                     |

Imagine that someone handed you a pile of 100 apples and then asked you to count how many of them were green without putting any of them down. You'd probably find this quite challenging and you'd struggle to hold the pile of apples at all. Now imagine someone handed you the apples one at a time and asked you to just count the green ones. This would be a much easier task.

In Python, when we use list comprehensions, it's like we've created the entire pile of apples and asked the interpreter to hold onto it. Sometimes, a better practice involves using generator expressions, which create iterators that yield objects one at a time. For large data sets, this can turn a slow, memory intensive operation into a relatively fast one.

Using generator expressions instead of list comprehensions can lead to better performance. This is especially true for functions such as `any` where it's not always necessary to evaluate the entire list before returning. For other functions such as `max` or `sum` it means that the program does not need to store the entire list in memory. These performance effects becomes more noticeable as the sizes of the lists involved grow large.

This codemod replaces the use of a list comprehension expression with a generator expression within certain function calls. Generators allow for lazy evaluation of the iterator, which can have performance benefits.

The changes from this codemod look like this:

```diff
- result = sum([x for x in range(1000)])
+ result = sum(x for x in range(1000))
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

We believe this replacement is safe and leads to better performance.

## Codemod Settings

N/A

## References

- [https://pylint.readthedocs.io/en/latest/user_guide/messages/refactor/use-a-generator.html](https://pylint.readthedocs.io/en/latest/user_guide/messages/refactor/use-a-generator.html)
- [https://docs.python.org/3/glossary.html#term-generator-expression](https://docs.python.org/3/glossary.html#term-generator-expression)
- [https://docs.python.org/3/glossary.html#term-list-comprehension](https://docs.python.org/3/glossary.html#term-list-comprehension)
