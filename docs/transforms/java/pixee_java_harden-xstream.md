---
title: Harden XStream usage
sidebar_position: 1
---


## pixee:java/harden-xstream
| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
 | High       | Merge Without Review | No                  |

This transform hardens usage of the `XStream` library to prevent remote code execution attacks.

XStream is a very flexible library, but it has a history of serious vulnerabilities when handling untrusted data because it was never intended for that use case. There are some fundamental issues with the design that make it difficult to make safe when using it by default.

Our change hardens new instances of `XStream` so that they can't deserialize types that are commonly used in exploits (and never in normal usage) and it looks like this:

```diff
XStream xstream = new XStream();
+xstream.registerConverter(HardeningConverter.INSTANCE);
```

Looking at the [history of exploits](https://x-stream.github.io/security.html#CVEs) shows that this change will either stop most exploits or raise the bar of exploitation. If you believe there should be more types added to the denylist, please [fill out a ticket](https://github.com/pixeeworks/java-code-hardener/issues/new) with your suggestions.

If you have feedback on this transform, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this transform marked as Merge Without Review?

We believe this change is safe and effective. The behavior of hardened `XStream` instances will only be different if the types being deserialized are involved in code execution, which is extremely unlikely to in normal operation.   

## Transform Settings

N/A

## References
* [Security Control (XMLInputFactorySecurity.java) source code](https://github.com/openpixee/java-security-toolkit/blob/main/src/main/java/io/openpixee/security/XMLInputFactorySecurity.java)
* [https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
* [https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md)