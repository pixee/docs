---
title: "CodeQL: Potential database resource leak"
sidebar_position: 1
---

## codeql:java/database-resource-leak 

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| Medium     | Merge Without Review | Yes (CodeQL)           |

This codemod adds [try-with-resources](https://docs.oracle.com/javase/tutorial/essential/exceptions/tryResourceClose.html) to JDBC code that is missing `close()` calls. Without explicit closing, these resources will be "leaked", and won't be re-claimed until garbage collection, leaving connections in an open state. In situations where these resources are leaked rapidly (either through malicious repetitive action or unusually spiky usage),  connection pool or file handle exhaustion will occur. These types of failures tend to be catastrophic, resulting in downtime and many times affect downstream applications.

Our changes look something like this:

```diff
- Statement stmt = conn.createStatement();
- ResultSet rs = stmt.executeQuery(query);
- // do stuff with results
+ try (Statement stmt = conn.createStatement()) {
+   ResultSet rs = stmt.executeQuery(query);
+   // do stuff with results
+ }
```

Although CodeQL labels this rule as "Potential", the codemod only acts on changes that are more provably vulnerable and safe to act on. Therefore, you may not see the codemod act on all findings of this type. 

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

This codemod causes database resources to be cleaned up immediately after use instead of at garbage collection time, and we don't believe this change entails any risk.  

## Codemod Settings

N/A

## References
* [https://codeql.github.com/codeql-query-help/java/java-database-resource-leak/](https://codeql.github.com/codeql-query-help/java/java-database-resource-leak/)
* [https://docs.oracle.com/javase/tutorial/essential/exceptions/tryResourceClose.html](https://docs.oracle.com/javase/tutorial/essential/exceptions/tryResourceClose.html)
* [https://cwe.mitre.org/data/definitions/404.html](https://cwe.mitre.org/data/definitions/404.html)
* [https://cwe.mitre.org/data/definitions/772.html](https://cwe.mitre.org/data/definitions/772.html)
