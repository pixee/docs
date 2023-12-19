---
title: "Sonar: Implemented parsing usage when converting Strings to primitives"
sidebar_position: 1
---

## sonar:java/harden-string-parse-to-primitives-s2130

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| Low        | Merge Without Review | Yes (Sonar)            |

This codemod updates `String`-to-number conversions by leveraging the intended parse methods.

This change makes developer intent clearer, and sometimes with a more concise expression.

Our changes look like this:

```diff
    String number = "7.1";

-   int integerNum = Integer.valueOf(number);
+   int integerNum = Integer.parseInt(number);

-   float floatNumVal = Float.valueOf(number).floatValue();
+   float floatNumVal = Float.parseFloat(number);

-   int integerNumber = new Integer(number);
+   int integerNumber = Integer.parseInt(number);
```


If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

There is no functional difference after the change, but the source code will be easier to understand.

## Codemod Settings

N/A

## References

* [https://rules.sonarsource.com/java/RSPEC-2130/](https://rules.sonarsource.com/java/RSPEC-2130/)