---
title: "Introduced protections against HTTP header injection / smuggling attacks"
sidebar_position: 1
---

## pixee:java/strip-http-header-newlines

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| MEDIUM     | Merge Without Review | No                     |

This change ensures that HTTP response header values can't contain newline characters, leaving you vulnerable to HTTP response splitting and other attacks.

If malicious users can get newline characters into an HTTP response header, they can inject and forge new header values that look like they came from the server, and trick web gateways, proxies, and browsers. This leads to vulnerabilities like Cross-site Scripting (XSS), HTTP response splitting, and more attacks from there.

Our change simply makes sure that if the string passed to be a new response header value is non-null, all the newline characters (CR and LF) will be removed:

```diff
+ import io.github.pixee.security.Newlines;
  ...
  String orderId = getUserOrderId();
- response.setHeader("X-Acme-Order-ID", orderId);
+ response.setHeader("X-Acme-Order-ID", Newlines.stripAll(orderId));
```

Note: Many modern application servers will sanitize these values, but it's almost never specified in documentation, and thus there is little guarantee against regression. Given that, we still recommend this practice.

## References

- [https://www.netsparker.com/blog/web-security/crlf-http-header/](https://www.netsparker.com/blog/web-security/crlf-http-header/)
- [https://owasp.org/www-community/attacks/HTTP_Response_Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting)
- [https://regilero.github.io/security/english/2015/10/04/http_smuggling_in_2015_part_one/](https://regilero.github.io/security/english/2015/10/04/http_smuggling_in_2015_part_one/)
