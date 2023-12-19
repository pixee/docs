---
title: "Sonar: Remove useless parentheses"
sidebar_position: 1
---

## sonar:java/remove-useless-parentheses-s1110

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| Low        | Merge Without Review | Yes (Sonar)            |

This codemod removes redundant parentheses. These extra parentheses make it harder to understand the code.

Our changes look something like this:

```diff

-     int leftOver = (int) (((bitCount >>> 3)) & 0x3f);
+     int leftOver = (int) ((bitCount >>> 3) & 0x3f);

```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

There should be no functional changes after this change, but the code should be easier to read. 

## Codemod Settings

N/A

## References

* [https://rules.sonarsource.com/java/RSPEC-1110/](https://rules.sonarsource.com/java/RSPEC-1110/)