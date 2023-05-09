---
title: Harden XMLInputFactory Usage
sidebar_position: 1
---


## pixee:java/harden-xmlinputfactory
| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
 | High       | Merge Without Review | No                  |

This codemod updates all instances of [XMLInputFactory](https://docs.oracle.com/javase/8/docs/api/javax/xml/stream/XMLInputFactory.html) to prevent them from resolving external entities, which can protect you from arbitrary code execution, sensitive data exfiltration, and an ever-growing list of other abuses attackers have discovered.

Without this protection, attackers can cause your `XMLInputFactory` parser to retrieve sensitive information with attacks like this:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<book>
    <title>&xxe;</title>
</book>
```

It is often surprising to developers that this is the default behavior. Our change hardens the factories you create with the necessary security features to prevent your parser from resolving external entities.

```diff
+ import io.github.pixee.security.XMLInputFactorySecurity;
  ...
- XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
+ XMLInputFactory xmlInputFactory = XMLInputFactorySecurity.hardenFactory(XMLInputFactory.newFactory());
```

You could take our protections one step further by changing our supplied code to prevent the user from supplying a `DOCTYPE`, which is more aggressive and more secure, but also more likely to affect existing code behavior:
```java
+ import io.github.pixee.security.XMLInputFactorySecurity;
+ import io.github.pixee.security.XMLRestrictions;
  ...
  XMLInputFactory xmlInputFactory = XMLInputFactorySecurity.hardenFactory(XMLInputFactory.newFactory(), XMLRestrictions.DISALLOW_DOCTYPE);
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this codemod marked as Merge Without Review?

We believe this change is safe and effective. The behavior of hardened `XMLInputFactory` instances will only be different if the XML they process uses external entities, which is exceptionally rare (and, as demonstrated, quite unsafe anyway.)   

## Codemod Settings

N/A

## References
* [Security Control (XMLInputFactorySecurity.java) source code](https://github.com/pixee/java-security-toolkit/blob/main/src/main/java/io/github/pixee/security/XMLInputFactorySecurity.java)
* [https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
* [https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md)