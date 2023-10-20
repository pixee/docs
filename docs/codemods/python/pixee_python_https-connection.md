---
title: Enforce HTTPS Connection for `urllib3`
sidebar_position: 1
---

## pixee:python/https-connection

| Importance | Review Guidance            | Requires SARIF Tool |
|------------|----------------------------|---------------------|
| High       | Merge Without Review | No                  |

This codemod replaces calls to `urllib3.connectionpool.HTTPConnectionPool` and `urllib3.HTTPConnectionPool` with their secure variant (`HTTPSConnectionPool`).

Programmers should opt to use HTTPS over HTTP for secure encrypted communication whenever possible.

```diff
import urllib3
- urllib3.HTTPConnectionPool("www.example.com","80")
+ urllib3.HTTPSConnectionPool("www.example.com","80")
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

Support for HTTPS is widespread which, save in some legacy applications, makes this change safe.

## Codemod Settings

N/A

## References

* [https://owasp.org/www-community/vulnerabilities/Insecure_Transport](https://owasp.org/www-community/vulnerabilities/Insecure_Transport)
* [https://urllib3.readthedocs.io/en/stable/reference/urllib3.connectionpool.html#urllib3.HTTPConnectionPool](https://urllib3.readthedocs.io/en/stable/reference/urllib3.connectionpool.html#urllib3.HTTPConnectionPool)
