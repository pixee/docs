---
title: "Use Safe Parameters in Django Response `set_cookie` Call"
sidebar_position: 1
---

## defectdojo:python/django-secure-set-cookie

| Importance | Review Guidance            | Requires Scanning Tool |
| ---------- | -------------------------- | ---------------------- |
| Medium     | Merge After Cursory Review | Yes (DefectDojo)       |

This codemod sets the most secure parameters when Django applications call `set_cookie` on a response object. Without these parameters, your Django application cookies may be vulnerable to being intercepted and used to gain access to sensitive data.

The changes from this codemod look like this:

```diff
 from django.shortcuts import render
 def index(request):
   resp = render(request, 'index.html')
 - resp.set_cookie('custom_cookie', 'value')
 + resp.set_cookie('custom_cookie', 'value', secure=True, httponly=True, samesite='Lax')
   return resp
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

Our change provides the most secure way to create cookies in Django. However, it's possible you have configured your Django application configurations to use secure cookies. In these cases, using the default parameters for `set_cookie` is safe.

## Codemod Settings

N/A

## References

N/A
