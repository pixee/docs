---
title: Switch Order of Literals
sidebar_position: 1
---

## pixee:java/switch-literal-first

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| Low        | Merge Without Review | No                     |

This codemod defensively switches the order of literals in comparison expressions to ensure that null pointer exceptions are not unexpectedly thrown. Runtime exceptions especially can cause exceptional and unexpected code paths to be taken, and this can result in unexpected behavior.

Both simple vulnerabilities (like information disclosure) and complex vulnerabilities (like business logic flaws) can take advantage of these unexpected code paths.

Our changes look something like this:

```diff
  String fieldName = header.getFieldName();
  String fieldValue = header.getFieldValue();
- if(fieldName.equals("requestId")) {
+ if("requestId".equals(fieldName)) {
    logRequest(fieldValue);
  }
```


If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

There should be no difference to code flow if the literal is first except in cases where the behavior is now fixed where a bug previously existed.

## References
 * [http://cwe.mitre.org/data/definitions/476.html](http://cwe.mitre.org/data/definitions/476.html)
 * [https://en.wikibooks.org/wiki/Java_Programming/Preventing_NullPointerException](https://en.wikibooks.org/wiki/Java_Programming/Preventing_NullPointerException)
 * [https://rules.sonarsource.com/java/RSPEC-1132/](https://rules.sonarsource.com/java/RSPEC-1132/)
