---
title: "Secure Setting for Django `SESSION_COOKIE_SECURE` flag"
sidebar_position: 1
---

## pixee:python/django-session-cookie-secure-off

| Importance | Review Guidance            | Requires Scanning Tool |
|------------|----------------------------|------------------------|
| Medium     | Merge After Cursory Review | No                     |

This codemod will set django's `SESSION_COOKIE_SECURE` flag to `True` if it's `False` or missing on the `settings.py` file within django's default directory structure.

```diff
+ SESSION_COOKIE_SECURE = True
```

Setting this flag on ensures that the session cookies are only sent under an HTTPS connection. Leaving this flag off may enable an attacker to use a sniffer to capture the unencrypted session cookie and hijack the user's session.

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

Django's `SESSION_COOKIE_SECURE` flag may be overridden somewhere else or the runtime settings file may be set with the `DJANGO_SETTINGS_MODULE` environment variable. This means that the flag may intentionally be left off or missing. Also some applications may still want to support pure http. This is often the case for legacy apps.

## Codemod Settings

N/A

## References

* [https://owasp.org/www-community/controls/SecureCookieAttribute](https://owasp.org/www-community/controls/SecureCookieAttribute)
* [https://docs.djangoproject.com/en/4.2/ref/settings/#session-cookie-secure](https://docs.djangoproject.com/en/4.2/ref/settings/#session-cookie-secure)
