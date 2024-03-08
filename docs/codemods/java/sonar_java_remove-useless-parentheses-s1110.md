---
title: "Remove useless parentheses (Sonar)"
sidebar_position: 1
---

## sonar:java/remove-useless-parentheses-s1110

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| LOW        | Merge Without Review | Yes (Sonar)            |

This change removes redundant parentheses. These extra parentheses make it harder to understand the code.

Our changes look something like this:

```diff

-     int leftOver = (int) (((bitCount >>> 3)) & 0x3f);
+     int leftOver = (int) ((bitCount >>> 3) & 0x3f);

```

## References

- [https://rules.sonarsource.com/java/RSPEC-1110/](https://rules.sonarsource.com/java/RSPEC-1110/)
