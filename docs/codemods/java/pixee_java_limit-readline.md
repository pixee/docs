---
title: "Protect `readLine()` against DoS"
sidebar_position: 1
---

## pixee:java/limit-readline 

| Importance  | Review Guidance      | Requires Scanning Tool |
|-------------|----------------------|------------------------|
| MEDIUM | Merge Without Review | No     |

This change hardens all [`BufferedReader#readLine()`](https://docs.oracle.com/javase/8/docs/api/java/io/BufferedReader.html#readLine--) operations against memory exhaustion.

There is no way to call `readLine()` safely since it is, by its nature, a read that must be terminated by the stream provider. Furthermore, a stream of data provided by an untrusted source could lead to a denial of service attack, as attackers can provide an infinite stream of bytes until the process runs out of memory.

Fixing it is straightforward using an API which limits the amount of expected characters to some sane limit. This is what our changes look like:

```diff
+ import io.github.pixee.security.BoundedLineReader;
  ...
  BufferedReader reader = getReader();
- String line = reader.readLine(); // unlimited read, can lead to DoS
+ String line = BoundedLineReader.readLine(reader, 5_000_000); // limited to 5MB
```

## F.A.Q.

### Why does this codemod require a Pixee dependency?

We always prefer to use existing controls built into Java, or a control from a well-known and trusted community dependency. However, we cannot find any such control. If you know of one, please let us know.


## References
 * [https://vulncat.fortify.com/en/detail?id=desc.dataflow.abap.denial_of_service](https://vulncat.fortify.com/en/detail?id=desc.dataflow.abap.denial_of_service)
 * [https://cwe.mitre.org/data/definitions/400.html](https://cwe.mitre.org/data/definitions/400.html)
