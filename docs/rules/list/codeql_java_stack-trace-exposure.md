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
* [Security Control (Urls.java) source code](https://github.com/openpixee/java-security-toolkit/blob/main/src/main/java/io/openpixee/security/Urls.java)
* [Security Control (HostValidator.java) source code](https://github.com/openpixee/java-security-toolkit/blob/main/src/main/java/io/openpixee/security/HostValidator.java)
* [https://portswigger.net/web-security/ssrf](https://portswigger.net/web-security/ssrf)
* [https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
* [https://www.rapid7.com/blog/post/2021/11/23/owasp-top-10-deep-dive-defending-against-server-side-request-forgery/](https://www.rapid7.com/blog/post/2021/11/23/owasp-top-10-deep-dive-defending-against-server-side-request-forgery/)
* [https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/](https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/)
