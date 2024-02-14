---
title: "Hardened XStream with a converter to prevent exploitation"
sidebar_position: 1
---

## pixee:java/harden-xstream 

| Importance  | Review Guidance      | Requires Scanning Tool |
|-------------|----------------------|------------------------|
| HIGH | Merge Without Review | No     |

This change hardens usage of the `XStream` library to prevent remote code execution attacks.

XStream is a very flexible library, but it has a history of serious vulnerabilities when handling untrusted data because it was never intended for that use case. There are some fundamental issues with the design that make it difficult to make safe when using it by default.

Our change hardens new instances of `XStream` so that they can't deserialize types that are commonly used in exploits (and never in normal usage) and it looks like this:

```diff
+ import io.github.pixee.security.xstream.HardeningConverter;
  XStream xstream = new XStream();
+ xstream.registerConverter(new HardeningConverter());
  return (AcmeObject)xstream.fromXML(xml);
```

Looking at the [history of exploits](https://x-stream.github.io/security.html#CVEs) shows that this change will either stop most exploits or raise the bar of exploitation. If you believe there should be more types added to the denylist, please [fill out a ticket](https://github.com/pixee/java-security-toolkit/issues/new) with your suggestions.

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

We believe this change is safe and effective. The behavior of hardened XStream instances will only be different if the types being deserialized are involved in code execution, which is extremely unlikely to in normal operation.


## References
 * [https://x-stream.github.io/security.html](https://x-stream.github.io/security.html)
 * [http://diniscruz.blogspot.com/2013/12/xstream-remote-code-execution-exploit.html](http://diniscruz.blogspot.com/2013/12/xstream-remote-code-execution-exploit.html)
 * [https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-2-xstream](https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-2-xstream)
 * [https://x-stream.github.io/CVE-2013-7285.html](https://x-stream.github.io/CVE-2013-7285.html)
