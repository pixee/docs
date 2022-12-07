---
title: JWT Signature Check
sidebar_position: 1
---

## codeql:java/jwt-signature-check 

| Importance | Review Guidance           | Requires SARIF Tool |
|------------|---------------------------|---------------------|
 | Medium     | Merge After Investigation | Yes (CodeQL)        |

This rule switches Json Web Token (JWT) parsing APIs to versions that perform signature validation.

Unfortunately the method names in JWT parsing with the `io.jsonwebtoken.jjwt` library don't convey the risk difference in usage. Although the `parseClaimsJws()` and `parseClaimsJwt()` methods perform signature validation, the `parse()` method does not.

Changing out these methods is easy and our changes look something like this:

```diff
JwtParser parser = Jwts.parser();
JwtParser jwtParser = parser.setSigningKey(JWT_PASSWORD);
-Jwt<Header, Claims> jwt = jwtParser.parse(token);
+Jwt<Header, Claims> jwt = jwtParser.parseClaimsJwt(token);
```

## F.A.Q.

### Why is this rule marked as Merge After Investigation?

This code may cause issues if the application is using tokens that can't be validated. This may happen if you're using this code anywhere you use self-signed JWTs. If you expect your tokens to be correctly generated and expect signature validation to be performed when processing JWTs, this change only reduces risk. However, one should be careful to ensure that CI, pre-production, and production are watched closely as this change moves towards deployment.   

## Rule Settings

N/A

## References
* [Security Control (Urls.java) source code](https://github.com/openpixee/java-security-toolkit/blob/main/src/main/java/io/openpixee/security/Urls.java)
* [Security Control (HostValidator.java) source code](https://github.com/openpixee/java-security-toolkit/blob/main/src/main/java/io/openpixee/security/HostValidator.java)
* [https://portswigger.net/web-security/ssrf](https://portswigger.net/web-security/ssrf)
* [https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
* [https://www.rapid7.com/blog/post/2021/11/23/owasp-top-10-deep-dive-defending-against-server-side-request-forgery/](https://www.rapid7.com/blog/post/2021/11/23/owasp-top-10-deep-dive-defending-against-server-side-request-forgery/)
* [https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/](https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/)
