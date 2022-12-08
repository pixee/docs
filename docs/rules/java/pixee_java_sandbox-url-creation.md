---
title: Sandbox URL Creation
sidebar_position: 1
---

## pixee:java/sandbox-url-creation 

| Importance | Review Guidance            | Requires SARIF Tool |
|------------|----------------------------|---------------------|
 | High       | Merge After Cursory Review | No                  |

This rule sandboxes the creation of [`java.net.URL`](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/net/URL.html) objects so they will be more resistant to Server-Side Request Forgery (SSRF) attacks.

Most of the time when you create a URL, you're intending to reference an HTTP endpoint, like an internal microservice. However, URLs can point to local file system files, a Gopher stream in your local network, a JAR file on a remote Internet site, and all kinds of other unexpected and undesirable outcomes. When the URL values are influenced by attackers, they can trick your application into fetching internal resources, running malicious code, or otherwise harming the system. Consider the following code:

```java
String url = userInput.getServiceAddress();
return IOUtils.toString(new URL(url).openConnection());
```

In this case, an attacker could supply a value like `jar:file:/path/to/appserver/lib.jar` and attempt to read the contents of your application's code.

Our changes introduce sandboxing around URL creation that force developers to specify some boundaries on the types of URLs they expect to create:

```diff
+import io.openpixee.security.HostValidator;
+import io.openpixee.security.Urls;
...
String url = userInput.getServiceAddress();
-URL u = new URL(url);
+URL u = Urls.create(url, Urls.HTTP_PROTOCOLS, HostValidator.DENY_COMMON_INFRASTRUCTURE_TARGETS);
InputStream is = u.openConnection();
```

This change alone reduces attack surface significantly, but it can be enhanced to create even more security by specifying some controls around the hosts we expect to connect with:

```java
import io.openpixee.security.HostValidator;
import io.openpixee.security.Urls;

HostValidator allowsOnlyGoodDotCom = HostValidator.fromAllowedHostPattern(Pattern.compile("good\\.com"));
URL u = Urls.create(url, Urls.HTTP_PROTOCOLS, allowsOnlyGoodDotCom);
```

Note: Be cautious about writing URL validation of your own. Parsing URLs is difficult and differences between parsers in validation and execution will certainly lead to exploits as attackers [have repeatedly proven](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf).

If you have feedback on this rule, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why does this rule require an OpenPixee dependency?

We always prefer to use existing controls built into Java, or a control from a well-known and trusted community dependency. However, we cannot find any such control. If you know of one, [please let us know](https://pixee.ai/feedback/).

### Why is this rule marked as Merge After Cursory Review?

By default, the protection only weaves in 2 checks, which we believe will not cause any issues with the vast majority of code:
1. The given URL must be HTTP/HTTPS.
2. The given URL must not point to a "well-known infrastructure target", which includes things like AWS Metadata Service endpoints, and internal routers (e.g., 192.168.1.1) which are common targets of attacks.

However, on rare occasions an application may use a URL protocol like "file://" or "classpath://" in backend or middleware code.

If you want to allow those protocols, change the incoming PR to look more like this and get the best security possible:

```java
-URL u = new URL(url);
+Set<UrlProtocol> fileProtocols = Set.of(UrlProtocol.FILE, UrlProtocol.CLASSPATH);
+URL u = Urls.create(url, fileProtocols);
```

## Rule Settings

N/A

## References
* [Security Control (Urls.java) source code](https://github.com/openpixee/java-security-toolkit/blob/main/src/main/java/io/openpixee/security/Urls.java)
* [Security Control (HostValidator.java) source code](https://github.com/openpixee/java-security-toolkit/blob/main/src/main/java/io/openpixee/security/HostValidator.java)
* [https://portswigger.net/web-security/ssrf](https://portswigger.net/web-security/ssrf)
* [https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
* [https://www.rapid7.com/blog/post/2021/11/23/owasp-top-10-deep-dive-defending-against-server-side-request-forgery/](https://www.rapid7.com/blog/post/2021/11/23/owasp-top-10-deep-dive-defending-against-server-side-request-forgery/)
* [https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/](https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/)
