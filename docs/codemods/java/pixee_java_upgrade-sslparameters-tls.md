---
title: "Upgraded SSLParameters#setProtocols() TLS versions to match current best practices"
sidebar_position: 1
---

## pixee:java/upgrade-sslparameters-tls

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| HIGH       | Merge Without Review | No                     |

This change ensures that `SSLParameters#setProtocols()` uses a safe version of Transport Layer Security (TLS), which is necessary for safe SSL connections.

TLS v1.0 and TLS v1.1 both have serious issues and are considered unsafe. Right now, the only safe version to use is 1.2.

Our change involves modifying the arguments to `setProtocols()` to return TLSv1.2 when it can be confirmed to be another, less secure value:

```diff
  SSLParameters sslParameters = ...;
- sslParameters.setProtocols(new String[] { "TLSv1.1" });
+ sslParameters.setProtocols(new String[] { "TLSv1.2" });
```

There is no functional difference between the unsafe and safe versions, and all modern servers offer TLSv1.2.

## References

- [https://datatracker.ietf.org/doc/rfc8996/](https://datatracker.ietf.org/doc/rfc8996/)
- [https://www.digicert.com/blog/depreciating-tls-1-0-and-1-1](https://www.digicert.com/blog/depreciating-tls-1-0-and-1-1)
