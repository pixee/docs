---
title: "Strengthened cipher seed with more unpredictable value"
sidebar_position: 1
---

## pixee:java/make-prng-seed-unpredictable

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| LOW        | Merge Without Review | No                     |

This change replaces all the constant seeds passed to `Random#setSeed(long)` with a pseudo-random value, which will make it considerably more secure.

A "seed" tells your pseudo-random number generator (PRNG) "where to start" in a deterministic (huge, but deterministic) set of numbers. If attackers can detect you're using a constant seed, they'll quickly be able to predict the next numbers you will generate.

Our change replaces the constant with `System#currentTimeMillis()`.

```diff
  Random random = new Random();
- random.setSeed(123);
+ random.setSeed(System.currentTimeMillis());
```

## References

- [https://wiki.sei.cmu.edu/confluence/display/c/MSC32-C.+Properly+seed+pseudorandom+number+generators](https://wiki.sei.cmu.edu/confluence/display/c/MSC32-C.+Properly+seed+pseudorandom+number+generators)
- [https://wiki.sei.cmu.edu/confluence/display/cplusplus/MSC51-CPP.+Ensure+your+random+number+generator+is+properly+seeded](https://wiki.sei.cmu.edu/confluence/display/cplusplus/MSC51-CPP.+Ensure+your+random+number+generator+is+properly+seeded)
- [https://cwe.mitre.org/data/definitions/337.html](https://cwe.mitre.org/data/definitions/337.html)
- [https://en.wikipedia.org/wiki/Random_seed](https://en.wikipedia.org/wiki/Random_seed)
