---
title: "Fixed inefficient usage of `String#replaceAll()` (Sonar)"
sidebar_position: 1
---

## sonar:java/substitute-replaceAll-s5361 

| Importance  | Review Guidance      | Requires Scanning Tool |
|-------------|----------------------|------------------------|
| MEDIUM | Merge Without Review | Yes (Sonar)     |

This change replaces `String#replaceAll()` with `String#replace()` to enhance performance and avoid confusion.

The `String#replaceAll()` call takes a regular expression for the first argument, which is then compiled and used to replace string subsections. However, the argument being passed to it doesn't actually appear to be a regular expression. Therefore, the `replace()` [API](https://docs.oracle.com/javase/8/docs/api/java/lang/String.html#replace-java.lang.CharSequence-java.lang.CharSequence-) appears to be a better fit.

Our changes look something like this:

```diff
    String init = "my string\n";

-   String changed = init.replaceAll("\n", "<br>");
+   String changed = init.replace("\n", "<br>");
```


## References
 * [https://rules.sonarsource.com/java/RSPEC-5361/](https://rules.sonarsource.com/java/RSPEC-5361/)
