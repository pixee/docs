---
title: "Replaced deprecated and insecure Apache HTTP client"
sidebar_position: 1
---

## pixee:java/replace-apache-defaulthttpclient 

| Importance  | Review Guidance      | Requires Scanning Tool |
|-------------|----------------------|------------------------|
| MEDIUM | Merge After Cursory Review | No     |

This change replaces all instances of the [deprecated `DefaultHttpClient`](https://hc.apache.org/httpcomponents-client-4.5.x/current/httpclient/apidocs/org/apache/http/impl/client/DefaultHttpClient.html) from Apache's HTTP client library with a more secure, modern implementation from the same package. 

 This type [does not support using TLS 1.2](https://find-sec-bugs.github.io/bugs.htm#DEFAULT_HTTP_CLIENT) and could be exposing the code to many different network security risks because of it.

Our changes look something like this:

```diff
- HttpClient client = new DefaultHttpClient();
+ HttpClient client = HttpClientBuilder.create().useSystemProperties().build();
```


## References
 * [https://find-sec-bugs.github.io/bugs.htm#DEFAULT_HTTP_CLIENT](https://find-sec-bugs.github.io/bugs.htm#DEFAULT_HTTP_CLIENT)
 * [https://www.ibm.com/support/pages/im-using-apache-httpclient-make-outbound-call-my-web-application-running-websphere-application-server-traditional-and-im-getting-ssl-handshake-error-how-can-i-debug](https://www.ibm.com/support/pages/im-using-apache-httpclient-make-outbound-call-my-web-application-running-websphere-application-server-traditional-and-im-getting-ssl-handshake-error-how-can-i-debug)
 * [https://cwe.mitre.org/data/definitions/326.html](https://cwe.mitre.org/data/definitions/326.html)
