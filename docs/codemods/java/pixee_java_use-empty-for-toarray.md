---
title: Pass Empty Array to Collection.toArray()
sidebar_position: 1
---

## pixee:java/use-empty-for-toarray

| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
| Low        | Merge Without Review | No                  |

This codemod updates new array creation with [Collection#toArray(T[])](https://docs.oracle.com/javase/8/docs/api/java/util/Collection.html#toArray-T:A-) to use an empty array argument, which is better for performance.

The point of the argument is provide an array to hold the objects and be returned, according to the documentation:

> If the collection fits in the specified array, it is returned therein.

Although it's not intuitive, allocating a right-sized array ahead of time to pass to the API appears to be [generally worse for performance](https://shipilev.net/blog/2016/arrays-wisdom-ancients/#_conclusion) according to benchmarking and JVM developers due to a number of implementation details in both Java and the virtual machine.   
 
For a real world example, consider [this issue in H2](https://github.com/h2database/h2database/issues/311) where significant gains were achieved by switching to an empty array instead of a right-sized one.

Our changes look something like this:

```diff
- int[] tokenArray = tokens.toArray(new int[tokens.size()]);
+ int[] tokenArray = tokens.toArray(new int[0]);
  processTokens(tokenArray);
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

There should be no difference to code flow if the literal is first except in cases where the behavior is now fixed where a bug previously existed.

## References
* [https://docs.pmd-code.org/latest/pmd_rules_java_performance.html#optimizabletoarraycall](https://docs.pmd-code.org/latest/pmd_rules_java_performance.html#optimizabletoarraycall)
* [https://shipilev.net/blog/2016/arrays-wisdom-ancients/#_conclusion](https://shipilev.net/blog/2016/arrays-wisdom-ancients/#_conclusion)
