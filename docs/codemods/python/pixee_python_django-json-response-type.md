---
title: "Set content type to `application/json` for `django.http.HttpResponse` with JSON data"
sidebar_position: 1
---

## pixee:python/django-json-response-type

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| Medium     | Merge Without Review | No                     |

The default `content_type` for `HttpResponse` in Django is `'text/html'`. This is true even when the response contains JSON data.
If the JSON contains (unsanitized) user-supplied input, a malicious user may supply HTML code which leaves the application vulnerable to cross-site scripting (XSS).
This fix explicitly sets the response type to `application/json` when the response body is JSON data to avoid this vulnerability. Our changes look something like this:

```diff
from django.http import HttpResponse
import json

def foo(request):
    json_response = json.dumps({ "user_input": request.GET.get("input") })
-    return HttpResponse(json_response)
+    return HttpResponse(json_response, content_type="application/json")
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

This change will only restrict the response type and will not alter the response data itself. Thus we deem it safe.

## Codemod Settings

N/A

## References

- [https://docs.djangoproject.com/en/4.0/ref/request-response/#django.http.HttpResponse.**init**](https://docs.djangoproject.com/en/4.0/ref/request-response/#django.http.HttpResponse.__init__)
- [https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#output-encoding-for-javascript-contexts](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#output-encoding-for-javascript-contexts)
