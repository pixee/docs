---
title: "Set private constructor to hide implicit public constructor (Sonar)"
sidebar_position: 1
---

## sonar:java/avoid-implicit-public-constructor-s1118

| Importance | Review Guidance    | Requires Scanning Tool |
| ---------- | ------------------ | ---------------------- |
| LOW        | Merge After Review | Yes (Sonar)            |

This change adds private constructors to utility classes. Utility classes are only meant to be accessed statically. Since they're not meant to be instantiated, we can use the Java's code visibility protections to hide the constructor and prevent unintended or malicious access.

Our changes look something like this:

```diff
   public class Utils {
+    private Utils() {}
     ...
```

## F.A.Q.

### Why is this codemod marked as Merge After Review?

This change depends completely on Sonar's accuracy about in identifying types that are meant to only offer static utilities. Our testing shows this generally works as expected, but correctness can't be guaranteed in all situations.

## References

- [https://rules.sonarsource.com/java/RSPEC-1118/](https://rules.sonarsource.com/java/RSPEC-1118/)
