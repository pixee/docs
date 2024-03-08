---
title: "Prevent resource leaks (CodeQL)"
sidebar_position: 1
---

## codeql:java/output-resource-leak

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| MEDIUM     | Merge Without Review | Yes (CodeQL)           |

This change adds [try-with-resources](https://docs.oracle.com/javase/tutorial/essential/exceptions/tryResourceClose.html) to code to prevent resources from being leaked, which could lead to denial-of-service conditions like connection pool or file handle exhaustion.

Our changes look something like this:

```diff
- BufferedWriter bw = new BufferedWriter(new FileWriter("C:\\test.txt"));
- bw.write("Hello world!");
+ try(FileWriter input = new FileWriter("C:\\test.txt")); BufferedWriter bw = new BufferedWriter(input)){
+   bw.write("Hello world!");
+ }
```

## References

- [https://codeql.github.com/codeql-query-help/java/java-output-resource-leak/](https://codeql.github.com/codeql-query-help/java/java-output-resource-leak/)
- [https://cwe.mitre.org/data/definitions/404.html](https://cwe.mitre.org/data/definitions/404.html)
- [https://cwe.mitre.org/data/definitions/772.html](https://cwe.mitre.org/data/definitions/772.html)
