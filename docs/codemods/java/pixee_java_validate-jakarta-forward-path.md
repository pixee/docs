---
title: Validate Jakarta Forwarding Path 
sidebar_position: 1
---

## pixee:java/validate-jakarta-forward-path

| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
| High       | Merge Without Review | No                  |

This codemod hardens all [`ServletRequest#getRequestDispatcher(String)`](https://docs.oracle.com/javaee/7/api/javax/servlet/ServletRequest.html#getRequestDispatcher-java.lang.String-) calls against attack.

There is a built-in HTTP method for sending clients to another resource: the [client-side redirect](https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections). However, the `getRequestDispatcher(String)` method is unique in that performs a forward which occurs totally within the _server-side_.

There is some security that usually comes within redirecting users back through the "front door". For instance, attackers could never directly request sensitive resources like `/WEB-INF/web.xml`. However, this isn't true for request dispatcher forwarding. Therefore, we must take special care that the path being forwarded isn't towards any known sensitive data.

Our change introduces an API that offers some validation against forwards that target sensitive data or attempt to access application code.

```diff
+import io.openpixee.security.Jakarta;
...
-request.getRequestDispatcher(path).forward(request, response);
+request.getRequestDispatcher(Jakarta.validateForwardPath(path)).forward(request, response);
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this codemod marked as Merge Without Review?

There is no reason an application should be forwarding to inner resources like `/WEB-INF/web.xml`, 

## Codemod Settings

N/A

## References

* [Security Control (Jakarta.java)](https://github.com/openpixee/java-security-toolkit/blob/main/src/main/java/io/openpixee/security/Jakarta.java)
* [https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html#dangerous-forward-example](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html#dangerous-forward-example)