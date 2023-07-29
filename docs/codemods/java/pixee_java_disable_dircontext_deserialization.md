---
title: Hardened LDAP Calls Against Deserialization Attacks
sidebar_position: 1
---

## pixee:java/disable-dircontext-deserialization 

| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
 | High       | Merge Without Review | No                  |

This codemod patches the LDAP interaction code to harden against a remote code execution vulnerability.

Using Java's deserialization APIs on untrusted data [is dangerous](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) because side effects from a type's reconstitution logic can be chained together to execute arbitrary code. This very serious and very common [bug class](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet) has resulted in some high profile vulnerabilities, including the [log4shell vulnerability](https://en.wikipedia.org/wiki/Log4Shell) that rocked the development and security world (and is [_still_ present in organizations](https://www.wired.com/story/log4j-log4shell-one-year-later/), by the way.)

Now, back to the change. The `DirContext#search(SearchControls)` API is used to send LDAP queries. If the `SearchControls` has the `retobj` set to `true`, the API will try to deserialize a piece of the response from the LDAP server with Java's deserialization API. This means that if the LDAP server could influenced to return malicious data (or is outright controlled by an attacker) then they could [execute arbitrary on the API client's JVM](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf).

Our changes look like this:

```diff
  DirContext ctx = new InitialDirContext();
- var results = ctx.search("query", "filter", new SearchControls(0, 0, 0, null, true, false));
+ var results = ctx.search("query", "filter", new SearchControls(0, 0, 0, null, false, false));
```



If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this codemod marked as Merge Without Review?

The protection works by denying deserialization during processing of an LDAP query which we're confident is intentional in a vanishingly small percentage of usage.

## Codemod Settings

N/A

## References
* [https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf)
* [https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
* [https://portswigger.net/web-security/deserialization/exploiting](https://portswigger.net/web-security/deserialization/exploiting)
