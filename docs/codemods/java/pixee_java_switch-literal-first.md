---
title: "Switch order of literals to prevent NullPointerException"
sidebar_position: 1
---

## pixee:java/switch-literal-first

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| LOW        | Merge Without Review | No                     |

This change defensively switches the order of literals in comparison expressions to ensure that no null pointer exceptions are unexpectedly thrown. Runtime exceptions especially can cause exceptional and unexpected code paths to be taken, and this can result in unexpected behavior.

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

## References

- [https://cwe.mitre.org/data/definitions/476.html](https://cwe.mitre.org/data/definitions/476.html)
- [https://en.wikibooks.org/wiki/Java_Programming/Preventing_NullPointerException](https://en.wikibooks.org/wiki/Java_Programming/Preventing_NullPointerException)
- [https://rules.sonarsource.com/java/RSPEC-1132/](https://rules.sonarsource.com/java/RSPEC-1132/)
