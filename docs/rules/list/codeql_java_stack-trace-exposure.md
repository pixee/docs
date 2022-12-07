---
title: Stack Trace Exposure
sidebar_position: 1
---

## codeql:java/stack-trace-exposure 

| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
 | High       | Merge Without Review | Yes (CodeQL)        |

This rule prevents stack trace information from reaching the HTTP response, which could leak code internals to an attacker and aid in further profiling and attacks.

Have you ever seen an error page and thought, "wow, I certainly shouldn't be seeing all these code details?" That's this problem.

Switching to a safe signature that doesn't leak anything is easy and the changes look something like this:

```diff
try {
  httpResponse.write(output);
} catch (Exception e) {
-  response.sendError(401, e.getMessage());
+  response.sendError(401);
}
```

## F.A.Q.

### Why is this rule marked as Merge Without Review?

This rule prevents internal coding details from reaching the HTTP response body, and we believe that fixing it presents zero risk.

## Rule Settings

N/A

## References
* [https://codeql.github.com/codeql-query-help/java/java-stack-trace-exposure/](https://codeql.github.com/codeql-query-help/java/java-stack-trace-exposure/)
* [https://cwe.mitre.org/data/definitions/209.html](https://cwe.mitre.org/data/definitions/209.html)
* [https://cwe.mitre.org/data/definitions/497.html](https://cwe.mitre.org/data/definitions/497.html)
