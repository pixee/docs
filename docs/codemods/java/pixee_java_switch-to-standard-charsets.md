---
title: "Switch to StandardCharsets fields instead of strings"
sidebar_position: 1
---

## pixee:java/switch-to-standard-charsets 

| Importance  | Review Guidance      | Requires Scanning Tool |
|-------------|----------------------|------------------------|
| LOW | Merge After Review | No     |

This change removes character set lookups with hardcoded strings like `"UTF-8"` in favor of referencing the `StandardCharsets` constants, which were [introduced in Java 7](https://docs.oracle.com/javase/7/docs/api/java/nio/charset/StandardCharsets.html).

This is faster, more predictable, and will remove the need for handling the `UnsupportedEncodingException`, which makes code easier to reason about. It will also remove IDE and compiler warnings.

Our changes look something like this:

```diff
  String s = getPropertyValue();
- byte[] b = s.getBytes("UTF-8");
+ byte[] b = s.getBytes(StandardCharsets.UTF_8);
```

Note: Further changes to exception handling may be needed.


## References
 * [https://community.sonarsource.com/t/use-standardcharsets-instead-of-charset-names/638](https://community.sonarsource.com/t/use-standardcharsets-instead-of-charset-names/638)
 * [https://github.com/pmd/pmd/issues/3190](https://github.com/pmd/pmd/issues/3190)
