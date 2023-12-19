---
title: "Sonar: Prevent utility class from instantiation"
sidebar_position: 1
---

## sonar:java/avoid-implicit-public-constructor-s1118

| Importance | Review Guidance            | Requires Scanning Tool |
|------------|----------------------------|------------------------|
| Low        | Merge After Cursory Review | Yes (Sonar)            |

This codemod adds private constructors to utility classes. Utility classes are only meant to be accessed statically. Since they're not meant to be instantiated, we can use the Java's code visibility protections to hide the constructor and prevent unintended or malicious access.

Our changes look something like this:

```diff
   public class Utils {
+    private Utils() {}
     ...
```


If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

This change depends completely on Sonar's accuracy about in identifying types that are meant to only offer static utilities. Our testing shows this generally works as expected, but correctness can't be guaranteed in all situations.

## Codemod Settings

N/A

## References

* [https://rules.sonarsource.com/java/RSPEC-1118/](https://rules.sonarsource.com/java/RSPEC-1118/)