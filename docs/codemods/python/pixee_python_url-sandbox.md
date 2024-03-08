---
title: "Sandbox URL Creation"
sidebar_position: 1
---

## pixee:python/url-sandbox

| Importance | Review Guidance            | Requires Scanning Tool |
| ---------- | -------------------------- | ---------------------- |
| High       | Merge After Cursory Review | No                     |

This codemod sandboxes calls to [`requests.get`](https://requests.readthedocs.io/en/latest/api/#requests.get) to be more resistant to Server-Side Request Forgery (SSRF) attacks.

Most of the time when you make a `GET` request to a URL, you're intending to reference an HTTP endpoint, like an internal microservice. However, URLs can point to local file system files, a Gopher stream in your local network, a JAR file on a remote Internet site, and all kinds of other unexpected and undesirable outcomes. When the URL values are influenced by attackers, they can trick your application into fetching internal resources, running malicious code, or otherwise harming the system.
Consider the following code for a Flask app:

```python
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route("/request-url")
def request_url():
    url = request.args["loc"]
    resp = requests.get(url)
    ...
```

In this case, an attacker could supply a value like `"http://169.254.169.254/user-data/"` and attempt to access user information.

Our changes introduce sandboxing around URL creation that force developers to specify some boundaries on the types of URLs they expect to create:

```diff
  from flask import Flask, request
- import requests
+ from security import safe_requests

  app = Flask(__name__)

  @app.route("/request-url")
  def request_url():
    url = request.args["loc"]
-   resp = requests.get(url)
+   resp = safe_requests.get(url)
    ...
```

This change alone reduces attack surface significantly because the default behavior of `safe_requests.get` raises a `SecurityException` if
a user attempts to access a known infrastructure location, unless specifically disabled.

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why does this codemod require a Pixee dependency?

We always prefer to use built-in Python functions or one from a well-known and trusted community dependency. However, we cannot find any such control. If you know of one, [please let us know](https://ask.pixee.ai/feedback).

### Why is this codemod marked as Merge After Cursory Review?

By default, the protection only weaves in 2 checks, which we believe will not cause any issues with the vast majority of code:

1. The given URL must be HTTP/HTTPS.
2. The given URL must not point to a "well-known infrastructure target", which includes things like AWS Metadata Service endpoints, and internal routers (e.g., 192.168.1.1) which are common targets of attacks.

However, on rare occasions an application may use a URL protocol like "file://" or "ftp://" in backend or middleware code.

If you want to allow those protocols, change the incoming PR to look more like this and get the best security possible:

```diff
-resp = requests.get(url)
+resp = safe_requests.get(url, allowed_protocols=("ftp",))
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

By default, the protection only weaves in 2 checks, which we believe will not cause any issues with the vast majority of code:

1. The given URL must be HTTP/HTTPS.
2. The given URL must not point to a "well-known infrastructure target", which includes things like AWS Metadata Service endpoints, and internal routers (e.g., 192.168.1.1) which are common targets of attacks.

However, on rare occasions an application may use a URL protocol like "file://" or "ftp://" in backend or middleware code.

If you want to allow those protocols, change the incoming PR to look more like this and get the best security possible:

```diff
-resp = requests.get(url)
+resp = safe_requests.get.get(url, allowed_protocols=("ftp",))
```

## Codemod Settings

N/A

## References

- [https://github.com/pixee/python-security/blob/main/src/security/safe_requests/api.py](https://github.com/pixee/python-security/blob/main/src/security/safe_requests/api.py)
- [https://portswigger.net/web-security/ssrf](https://portswigger.net/web-security/ssrf)
- [https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [https://www.rapid7.com/blog/post/2021/11/23/owasp-top-10-deep-dive-defending-against-server-side-request-forgery/](https://www.rapid7.com/blog/post/2021/11/23/owasp-top-10-deep-dive-defending-against-server-side-request-forgery/)
- [https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/](https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/)
