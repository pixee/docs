---
title: "Prevent resource leaks (CodeQL)"
sidebar_position: 1
---

## codeql:java/input-resource-leak

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| MEDIUM     | Merge Without Review | Yes (CodeQL)           |

This change adds [try-with-resources](https://docs.oracle.com/javase/tutorial/essential/exceptions/tryResourceClose.html) to code to prevent resources from being leaked, which could lead to denial-of-service conditions like connection pool or file handle exhaustion.

Our changes look something like this:

```diff
- BufferedReader br = new BufferedReader(new FileReader("C:\\test.txt"));
- System.out.println(br.readLine());
+ try(FileReader input = new FileReader("C:\\test.txt"); BufferedReader br = new BufferedReader(input)){
+   System.out.println(br.readLine());
+ }
```

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

This codemod causes resources to be cleaned up immediately after use instead of at garbage collection time, and we don't believe this change entails any risk.

## References

- [https://codeql.github.com/codeql-query-help/java/java-input-resource-leak/](https://codeql.github.com/codeql-query-help/java/java-input-resource-leak/)
- [https://cwe.mitre.org/data/definitions/404.html](https://cwe.mitre.org/data/definitions/404.html)
- [https://cwe.mitre.org/data/definitions/772.html](https://cwe.mitre.org/data/definitions/772.html)
