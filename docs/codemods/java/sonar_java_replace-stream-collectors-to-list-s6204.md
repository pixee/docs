---
title: "Sonar: Simplify Stream#collect(Collectors#toList()) to Stream#toList()"
sidebar_position: 1
---

## sonar:java/replace-stream-collectors-to-list-s6204

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| Low        | Merge Without Review | Yes (Sonar)            |

This change modernizes a stream's `List` creation to be driven from the simple, and more readable [`Stream#toList()`](https://docs.oracle.com/javase/16/docs/api/java.base/java/util/stream/Collectors.html#toList()) method.

Our changes look something like this:

```diff
- List<Integer> numbers = someStream.collect(Collectors.toList());
+ List<Integer> numbers = someStream.toList();
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

There should be no functional changes after this change, but the code should be easier to read. 

## Codemod Settings

N/A

## References

* [https://rules.sonarsource.com/java/RSPEC-6204/](https://rules.sonarsource.com/java/RSPEC-6204/)