---
title: Flip Insecure `Flask` Session Configurations
sidebar_position: 1
---

## pixee:python/secure-flask-session-configuration

| Importance | Review Guidance    | Requires Scanning Tool |
|------------|--------------------|------------------------|
| Medium     | Merge After Review | No                     |

Flask applications can configure sessions behavior at the application level. 
This codemod looks for Flask application configuration that set `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SECURE`, or `SESSION_COOKIE_SAMESITE` to an insecure value and changes it to a secure one.

The changes from this codemod look like this:

```diff
  from flask import Flask
  app = Flask(__name__)
- app.config['SESSION_COOKIE_HTTPONLY'] = False
- app.config.update(SESSION_COOKIE_SECURE=False)
+ app.config['SESSION_COOKIE_HTTPONLY'] = True
+ app.config.update(SESSION_COOKIE_SECURE=True)
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Review?

Our change fixes explicitly insecure session configuration for a Flask application. However, there may be valid cases to use these insecure configurations, such as for testing or backward compatibility.

## Codemod Settings

N/A

## References

* [https://owasp.org/www-community/controls/SecureCookieAttribute](https://owasp.org/www-community/controls/SecureCookieAttribute)
* [https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
