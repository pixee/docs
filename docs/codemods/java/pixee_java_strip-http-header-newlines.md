---
title: Sanitize Newlines in HTTP Headers
sidebar_position: 1
---

## pixee:java/strip-http-header-newlines

| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
| Medium     | Merge Without Review | No                  |

This codemod ensures that HTTP response header values can't contain newline characters, which could disrupt communication with proxies and possibly leave you vulnerable to protocol-based attacks.

If malicious users can get newline characters into an HTTP response header, they can inject and forge new header values that look like they came from the server, and trick web gateways, proxies, and browsers. This leads to vulnerabilities like Cross-site Scripting (XSS), HTTP response splitting, and more attacks from there.

Our change simply makes sure that if the string passed to be a new response header value is non-null, all the newline characters (CR and LF) will be removed: 
```diff
+import io.openpixee.security.Newlines;
...
String orderId = getUserOrderId();
-response.setHeader("X-Acme-Order-ID", orderId);
+response.setHeader("X-Acme-Order-ID", Newlines.stripAll(orderId));
```

Note: Many modern application servers will sanitize these values, but it's almost never specified in documentation, and thus there is little guarantee against regression. Given that, we still recommend this practice.


If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this codemod marked as Merge Without Review?

This codemod cleanly enforces the boundaries in the HTTP protocol, and we believe it presents no risk.

## Codemod Settings

N/A

## References
* [https://www.netsparker.com/blog/web-security/crlf-http-header/](https://www.netsparker.com/blog/web-security/crlf-http-header/)
* [https://owasp.org/www-community/attacks/HTTP_Response_Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting)
* [https://regilero.github.io/security/english/2015/10/04/http_smuggling_in_2015_part_one/](https://regilero.github.io/security/english/2015/10/04/http_smuggling_in_2015_part_one/)
