---
title: Use Safe Parameters in `flask` Response `set_cookie` Call
sidebar_position: 1
---

## pixee:python/secure-flask-cookie

| Importance | Review Guidance            | Requires Scanning Tool |
|------------|----------------------------|------------------------|
| Medium     | Merge After Cursory Review | No                     |

This codemod sets the most secure parameters when Flask applications call `set_cookie` on a response object. Without these parameters, your Flask
application cookies may be vulnerable to being intercepted and used to gain access to sensitive data.

The changes from this codemod look like this:

```diff
  from flask import Flask, session, make_response
  app = Flask(__name__)
  @app.route('/')
    def index():
      resp = make_response('Custom Cookie Set')
    - resp.set_cookie('custom_cookie', 'value')
    + resp.set_cookie('custom_cookie', 'value', secure=True, httponly=True, samesite='Lax')
      return resp
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

Our change provides the most secure way to create cookies in Flask. However, it's possible you have configured your Flask application configurations to use secure cookies. In these cases, using the default parameters for `set_cookie` is safe.

## Codemod Settings

N/A

## References

* [https://flask.palletsprojects.com/en/3.0.x/api/#flask.Response.set_cookie](https://flask.palletsprojects.com/en/3.0.x/api/#flask.Response.set_cookie)
* [https://owasp.org/www-community/controls/SecureCookieAttribute](https://owasp.org/www-community/controls/SecureCookieAttribute)
