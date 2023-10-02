---
title: Enable Jinja2 Autoescape
sidebar_position: 1
---

## pixee:python/enable-jinja2-autoescape

| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
 | High       | Merge Without Review | No                  |

This codemod enables autoescaping of HTML content in `jinja2`. Unfortunately, the jinja2
default behavior is to not autoescape when rendering templates, which makes your applications
potentially vulnerable to Cross-Site Scripting (XSS) attacks.

Our codemod checks if you forgot to enable autoescape or if you explicitly disabled it. The change looks as follows:

```diff
  from jinja2 import Environment

- env = Environment()
- env = Environment(autoescape=False, loader=some_loader)
+ env = Environment(autoescape=True)
+ env = Environment(autoescape=True, loader=some_loader)
  ...
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this codemod marked as Merge Without Review?

This codemod protects your applications against XSS attacks. We believe using the default behavior is unsafe.

## References
* [https://owasp.org/www-community/attacks/xss/](https://owasp.org/www-community/attacks/xss/)
* [https://jinja.palletsprojects.com/en/3.1.x/api/#autoescaping](https://jinja.palletsprojects.com/en/3.1.x/api/#autoescaping)
