---
title: Upgrade SSLContext Minimum Version
sidebar_position: 1
---

## pixee:python/upgrade-sslcontext-minimum-version

| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
| High     | Merge Without Review | No                  |

This codemod replaces all unsafe and/or deprecated SSL/TLS versions when used
to set the `ssl.SSLContext.minimum_version` attribute. It uses
`ssl.TLSVersion.TLSv1_2` instead, which ensures a safe default minimum TLS
version.

Our change involves modifying the `minimum_version` attribute of
`ssl.SSLContext` instances to use `ssl.TLSVersion.TLSv1_2`.

```diff
  import ssl
  context = ssl.SSLContext(protocol=PROTOCOL_TLS_CLIENT)
- context.minimum_version = ssl.TLSVersion.SSLv3
+ context.minimum_version = ssl.TLSVersion.TLSv1_2
```

There is no functional difference between the unsafe and safe versions, and all modern servers offer TLSv1.2.

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this codemod marked as Merge Without Review?

This codemod updates the minimum supported version of TLS. Since this is an
important security fix and since all modern servers offer TLSv1.2, we believe
this change can be safely merged without review.

## References

* [https://docs.python.org/3/library/ssl.html#security-considerations](https://docs.python.org/3/library/ssl.html#security-considerations)
* [https://datatracker.ietf.org/doc/rfc8996/](https://datatracker.ietf.org/doc/rfc8996/)
* [https://www.digicert.com/blog/depreciating-tls-1-0-and-1-1](https://www.digicert.com/blog/depreciating-tls-1-0-and-1-1)
