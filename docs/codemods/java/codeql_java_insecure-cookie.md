---
title: "Added secure flag to HTTP cookies (CodeQL)"
sidebar_position: 1
---

## codeql:java/insecure-cookie 

| Importance  | Review Guidance      | Requires Scanning Tool |
|-------------|----------------------|------------------------|
| LOW | Merge Without Review | Yes (CodeQL)     |

This change marks new cookies sent in the HTTP with the ["secure" flag](https://owasp.org/www-community/controls/SecureCookieAttribute). This flag, despite its ambitious name, only provides one type of protection: confidentiality. Cookies with this flag are guaranteed by the browser never to be sent over a cleartext channel ("http://") and only sent over secure channels ("https://").

Our change introduces this flag with a simple 1-line statement:

```diff
  Cookie cookie = new Cookie("my_cookie", userCookieValue);
+ cookie.setSecure(true);
  response.addCookie(cookie);
```

Note: this code change **may cause issues** with the application if any of the places this code runs (in CI, pre-production or in production) are running in non-HTTPS protocol.

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

This code change may cause issues with the application if any of the places this code runs (in CI, pre-production or in production) are running over plaintext HTTP.


## References
 * [https://codeql.github.com/codeql-query-help/java/java-insecure-cookie/](https://codeql.github.com/codeql-query-help/java/java-insecure-cookie/)
 * [https://owasp.org/www-community/controls/SecureCookieAttribute](https://owasp.org/www-community/controls/SecureCookieAttribute)
 * [https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
 * [https://cwe.mitre.org/data/definitions/614.html](https://cwe.mitre.org/data/definitions/614.html)
