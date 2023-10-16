---
title: Flip Django Debug Flag to Off
sidebar_position: 1
---

## pixee:python/django-debug-flag-on

| Importance | Review Guidance            | Requires SARIF Tool |
|------------|----------------------------|---------------------|
| Medium       | Merge After Cursory Review | No                  |

This codemod will flip django's `DEBUG` flag to `False` if it's `True` on the `settings.py` file within django's default directory structure.

Having the debug flag on may result in sensitive information exposure. When an exception occurs while the `DEBUG` flag in on, it will dump metadata of your environment, including the settings module. The attacker can purposefully request a non-existing url to trigger an exception and gather information about your system.

```diff
- DEBUG = True
+ DEBUG = False
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

Django's `DEBUG` flag may be overridden somewhere else or the runtime settings file may be set with the `DJANGO_SETTINGS_MODULE` environment variable. This means that the `DEBUG` flag may intentionally be left on as a development aid.

## Codemod Settings

N/A

## References

* [https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)
* [https://docs.djangoproject.com/en/4.2/ref/settings/#std-setting-DEBUG](https://docs.djangoproject.com/en/4.2/ref/settings/#std-setting-DEBUG)
