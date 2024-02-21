---
title: "Verify JWT Decode"
sidebar_position: 1
---

## pixee:python/jwt-decode-verify

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| High       | Merge Without Review | No                     |

This codemod ensures calls to [jwt.decode](https://pyjwt.readthedocs.io/en/stable/api.html#jwt.decode) do not disable signature validation and other verifications. It checks that both the `verify` parameter (soon to be deprecated) and any `verify` key in the `options` dict parameter are not assigned to `False`.

Our change looks as follows:

```diff
  import jwt
  ...
- decoded_payload = jwt.decode(encoded_jwt, SECRET_KEY, algorithms=["HS256"], verify=False)
+ decoded_payload = jwt.decode(encoded_jwt, SECRET_KEY, algorithms=["HS256"], verify=True)
  ...
- decoded_payload = jwt.decode(encoded_jwt, SECRET_KEY, algorithms=["HS256"], options={"verify_signature": False, "verify_exp": False})
+ decoded_payload = jwt.decode(encoded_jwt, SECRET_KEY, algorithms=["HS256"], options={"verify_signature": True, "verify_exp": True})
```

Any `verify` parameter not listed relies on the secure `True` default value.

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

This codemod ensures your code uses all available validations when calling `jwt.decode`. We believe this replacement is safe and should not result in any issues.

## Codemod Settings

N/A

## References

* [https://pyjwt.readthedocs.io/en/stable/api.html](https://pyjwt.readthedocs.io/en/stable/api.html)
* [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens)
