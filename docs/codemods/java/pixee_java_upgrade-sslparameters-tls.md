---
title: Upgrade TLS Version in SSLParameters 
sidebar_position: 1
---

## pixee:java/upgrade-sslparameters-tls

| Importance | Review Guidance            | Requires SARIF Tool |
|------------|----------------------------|---------------------|
| High       | Merge After Cursory Review | No                  |

This codemod ensures that `SSLParameters#setProtocols()` uses a safe version of Transport Layer Security (TLS), which is necessary for safe SSL connections.

TLS v1.0 and TLS v1.1 both have serious issues and are considered unsafe. Right now, the only safe version to use is 1.2.

Our change involves modifying the arguments to `setProtocols()` to return TLSv1.2 when it can be confirmed to be another, less secure value:

```diff
SSLParameters sslParameters = ...;
-sslParameters.setProtocols(new String[] { "TLSv1.1" });
+sslParameters.setProtocols(new String[] { "TLSv1.2" });
```

There is no functional difference between the unsafe and safe versions, and all modern servers offer TLSv1.2.

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this codemod marked as Merge After Cursory Review?

There is only a risk of this codemod introducing issues if the other party in the communication doesn't support modern versions of TLS. This should be extremely rare as those older versions are no longer honored by browsers or supported by most server software.

## Codemod Settings

N/A

## References

* [https://datatracker.ietf.org/doc/rfc8996/](https://datatracker.ietf.org/doc/rfc8996/)
* [https://www.digicert.com/blog/depreciating-tls-1-0-and-1-1](https://www.digicert.com/blog/depreciating-tls-1-0-and-1-1)