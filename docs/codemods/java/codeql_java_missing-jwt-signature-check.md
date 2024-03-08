---
title: "Switch JWT calls to versions that enforce signature validity (CodeQL)"
sidebar_position: 1
---

## codeql:java/missing-jwt-signature-check

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| MEDIUM     | Merge Without Review | Yes (CodeQL)           |

This change switches to Json Web Token (JWT) parsing APIs that perform signature validation.

Unfortunately the method names in JWT parsing with the `io.jsonwebtoken.jjwt` library don't convey the risk difference in usage. Although the `parseClaimsJws()` and `parseClaimsJwt()` methods perform signature validation, the `parse()` method does not.

Changing out these methods is easy and our changes look something like this:

```diff
  JwtParser parser = Jwts.parser();
  JwtParser jwtParser = parser.setSigningKey(JWT_PASSWORD);
- Jwt<Header, Claims> jwt = jwtParser.parse(token);
+ Jwt<Header, Claims> jwt = jwtParser.parseClaimsJwt(token);
```

## References

- [https://codeql.github.com/codeql-query-help/java/java-missing-jwt-signature-check/](https://codeql.github.com/codeql-query-help/java/java-missing-jwt-signature-check/)
- [https://cwe.mitre.org/data/definitions/347.html](https://cwe.mitre.org/data/definitions/347.html)
