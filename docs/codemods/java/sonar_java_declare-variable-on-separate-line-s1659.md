---
title: "Sonar: Declare variable on separate line"
sidebar_position: 1
---

## sonar:java/declare-variable-on-separate-line-s1659

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| Low        | Merge Without Review | Yes (Sonar)            |

This change splits variable assignments onto their own lines. [Many](https://wiki.sei.cmu.edu/confluence/display/java/DCL52-J.+Do+not+declare+more+than+one+variable+per+declaration) [sources](https://rules.sonarsource.com/java/RSPEC-1659/) [believe](https://dart.dev/tools/linter-rules/avoid_multiple_declarations_per_line) it is easier to review code where the variables are separate statements on their own individual line.

Our changes look something like this:

```diff
-   int i = 0, limit = 10;
+   int i = 0;
+   int limit = 10;

    while (i < limit){
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

There is no functional difference after the change, but the source code will be easier to understand.

## Codemod Settings

N/A

## References

* [https://rules.sonarsource.com/java/RSPEC-1659/](https://rules.sonarsource.com/java/RSPEC-1659/)