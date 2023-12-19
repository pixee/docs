---
title: Make PRNG Seed Unpredictable
sidebar_position: 1
---

## pixee:java/make-prng-seed-unpredictable

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
 | Low        | Merge Without Review | No                     |

This codemod replaces all the constant seeds passed to `Random#setSeed(long)` with a pseudo-random value, which will make it considerably more secure.

A "seed" tells your pseudo-random number generator (PRNG) "where to start" in a deterministic (large, but deterministic) set of numbers. If attackers can detect you're using a constant seed, they'll quickly be able to predict the next numbers you will generate.

Our change replaces the constant with [`System#currentTimeMillis()`](https://docs.oracle.com/javase/7/docs/api/java/lang/System.html#currentTimeMillis()):

```diff
  Random random = new Random();
- random.setSeed(123);
+ random.setSeed(System.currentTimeMillis());
```


If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this codemod marked as Merge Without Review?

There should be no difference to the code what random numbers are generated. If there is, this change will surface that issue. This case could indicate a serious security weakness.

## References

* [https://wiki.sei.cmu.edu/confluence/display/c/MSC32-C.+Properly+seed+pseudorandom+number+generators](https://wiki.sei.cmu.edu/confluence/display/c/MSC32-C.+Properly+seed+pseudorandom+number+generators)
* [https://wiki.sei.cmu.edu/confluence/display/cplusplus/MSC51-CPP.+Ensure+your+random+number+generator+is+properly+seeded](https://wiki.sei.cmu.edu/confluence/display/cplusplus/MSC51-CPP.+Ensure+your+random+number+generator+is+properly+seeded)
* [https://cwe.mitre.org/data/definitions/337.html](https://cwe.mitre.org/data/definitions/337.html)
* [https://en.wikipedia.org/wiki/Random_seed](https://en.wikipedia.org/wiki/Random_seed)