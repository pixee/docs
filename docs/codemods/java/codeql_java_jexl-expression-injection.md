---
title: "Expression language injection (JEXL) (CodeQL)"
sidebar_position: 1
---

## codeql:java/jexl-expression-injection

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| MEDIUM     | Merge Without Review | Yes (CodeQL)           |

This change adds [a sandbox](https://commons.apache.org/proper/commons-jexl/apidocs/org/apache/commons/jexl3/introspection/JexlSandbox.html) to JEXL expression evaluation. This sandbox prevents access to many types that don't appear in typical usage, but are very common in exploits.

Sandboxing helps tremendously, but depending on the attacker profile, the information they have, what's on the classpath, and other factors, there may be exploitation paths that don't go through any well-known "evil types". Thus, although we think this is a necessary step, further controls may be warranted.

Our changes look something like this:

```diff
+ import io.github.pixee.security.UnwantedTypes;
  String input = message.read();
+ JexlSandbox sandbox = new JexlSandbox(true);
+ for (String cls : UnwantedTypes.all()) {
+   sandbox.block(cls);
+ }
- JexlEngine jexl = new JexlBuilder().create();
+ JexlEngine jexl = new JexlBuilder().sandbox(sandbox).create();
  JexlExpression expression = jexl.createExpression(input);
  JexlContext context = new MapContext();
  expression.evaluate(context);
```

## References

- [https://codeql.github.com/codeql-query-help/java/java-jexl-expression-injection/](https://codeql.github.com/codeql-query-help/java/java-jexl-expression-injection/)
- [https://commons.apache.org/proper/commons-jexl/apidocs/org/apache/commons/jexl3/introspection/JexlSandbox.html](https://commons.apache.org/proper/commons-jexl/apidocs/org/apache/commons/jexl3/introspection/JexlSandbox.html)
- [https://cwe.mitre.org/data/definitions/693.html](https://cwe.mitre.org/data/definitions/693.html)
- [https://cwe.mitre.org/data/definitions/94.html](https://cwe.mitre.org/data/definitions/94.html)
