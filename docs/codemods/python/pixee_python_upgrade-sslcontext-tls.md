---
title: Upgrade TLS Version In SSLContext
sidebar_position: 1
---

## pixee:python/upgrade-sslcontext-tls

| Importance | Review Guidance            | Requires SARIF Tool |
|------------|----------------------------|---------------------|
| High       | Merge After Cursory Review | No                  |

This codemod replaces the use of all unsafe and/or deprecated SSL/TLS versions
in the `ssl.SSLContext` constructor. It uses `PROTOCOL_TLS_CLIENT` instead,
which ensures a safe default TLS version. It also sets the `protocol` parameter
to `PROTOCOL_TLS_CLIENT` in calls without it, which is now deprecated.

Our change involves modifying the argument to `ssl.SSLContext()` to
use `PROTOCOL_TLS_CLIENT`.

```diff
  import ssl
- context = ssl.SSLContext()  
+ context = ssl.SSLContext(protocol=PROTOCOL_TLS_CLIENT)
- context = ssl.SSLContext(protocol=PROTOCOL_SSLv3)
+ context = ssl.SSLContext(protocol=PROTOCOL_TLS_CLIENT)
```

There is no functional difference between the unsafe and safe versions, and all modern servers offer TLSv1.2.

The use of explicit TLS versions (even safe ones) is deprecated by the `ssl`
module, so it is necessary to choose either `PROTOCOL_TLS_CLIENT` or
`PROTOCOL_TLS_SERVER`. Using `PROTOCOL_TLS_CLIENT` is expected to be the
correct choice for most applications but in some cases it will be necessary to
use `PROTOCOL_TLS_SERVER` instead.

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

This codemod updates the minimum supported version of TLS. Since this is an important security fix and since all modern servers offer TLSv1.2, we believe this change can be safely merged without review.

## Codemod Settings

N/A

## References

* [https://docs.python.org/3/library/ssl.html#security-considerations](https://docs.python.org/3/library/ssl.html#security-considerations)
* [https://datatracker.ietf.org/doc/rfc8996/](https://datatracker.ietf.org/doc/rfc8996/)
* [https://www.digicert.com/blog/depreciating-tls-1-0-and-1-1](https://www.digicert.com/blog/depreciating-tls-1-0-and-1-1)
