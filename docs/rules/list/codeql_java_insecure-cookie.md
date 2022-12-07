---
title: Secure Cookie Transmission
sidebar_position: 1
---

## codeql:java/insecure-cookie 

| Importance | Review Guidance           | Requires SARIF Tool |
|------------|---------------------------|---------------------|
 | Low        | Merge After Investigation | Yes (CodeQL)        |

This rule marks new HTTP cookies with the ["secure" flag](https://owasp.org/www-community/controls/SecureCookieAttribute). This flag, despite its ambitious name, only provides one type of protection: confidentiality. Cookies with this flag are guaranteed by the browser never to be sent over a cleartext channel ("http://") and only sent over secure channels ("https://").

Our change introduces this flag with a simple 1-line statement:

```diff
Cookie cookie = new Cookie("my_cookie", userCookieValue);
+cookie.setSecure(true);
response.addCookie(cookie);
```

## F.A.Q.

### Why is this rule marked as Merge After Investigation?

This code change may cause issues with the application if any of the places this code runs (in CI, pre-production or in production) are running with non-HTTPS protocol.

## Rule Settings

N/A

## References
* [Security Control (Urls.java) source code](https://github.com/openpixee/java-security-toolkit/blob/main/src/main/java/io/openpixee/security/Urls.java)
* [Security Control (HostValidator.java) source code](https://github.com/openpixee/java-security-toolkit/blob/main/src/main/java/io/openpixee/security/HostValidator.java)
* [https://portswigger.net/web-security/ssrf](https://portswigger.net/web-security/ssrf)
* [https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
* [https://www.rapid7.com/blog/post/2021/11/23/owasp-top-10-deep-dive-defending-against-server-side-request-forgery/](https://www.rapid7.com/blog/post/2021/11/23/owasp-top-10-deep-dive-defending-against-server-side-request-forgery/)
* [https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/](https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/)
