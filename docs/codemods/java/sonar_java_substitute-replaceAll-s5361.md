---
title: "Sonar: Fixed inefficient usage of String#replaceAll()"
sidebar_position: 1
---

## sonar:java/substitute-replaceAll-s5361

| Importance | Review Guidance            | Requires Scanning Tool |
|------------|----------------------------|------------------------|
| Medium     | Merge After Cursory Review | Yes (Sonar)            |

This codemod replaces `String#replaceAll()` with `String#replace()` to enhance performance and avoid confusion.

The `String#replaceAll()` call takes a regular expression for the first argument, which is then compiled and used to replace string subsections. However, the argument being passed to it doesn't actually appear to be a regular expression. Therefore, the `replace()` [API](https://docs.oracle.com/javase/8/docs/api/java/lang/String.html#replace-java.lang.CharSequence-java.lang.CharSequence-) appears to be a better fit.

Our changes look something like this:

```diff
    String init = "my string\n";

-   String changed = init.replaceAll("\n", "<br>");
+   String changed = init.replace("\n", "<br>");
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

There should be no functional changes after this change, but this depends on Sonar's accuracy Sonar in assessing whether the first argument contains regex metacharacters. Our testing shows this is a safe assumption, but the behavior can't be guaranteed. 

## Codemod Settings

N/A

## References

* [https://rules.sonarsource.com/java/RSPEC-5361/](https://rules.sonarsource.com/java/RSPEC-5361/)