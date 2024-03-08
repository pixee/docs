---
title: "Verify SSL Certificates for Requests."
sidebar_position: 1
---

## pixee:python/requests-verify

| Importance | Review Guidance            | Requires Scanning Tool |
| ---------- | -------------------------- | ---------------------- |
| High       | Merge After Cursory Review | No                     |

This codemod checks that calls to the `requests` module API or the `httpx` library use `verify=True` or a path to a CA bundle to ensure TLS certificate validation.

The [requests documentation](https://requests.readthedocs.io/en/latest/api/) warns that the `verify` flag

> When set to False, requests will accept any TLS certificate presented by the server, and will ignore hostname mismatches and/or expired certificates, which will make your application vulnerable to man-in-the-middle (MitM) attacks. Setting verify to False may be useful during local development or testing.

Similarly, setting `verify=False` when using the `httpx` library to make requests disables certificate verification.

The changes from this codemod look like this:

```diff
  import requests

- requests.get("www.google.com", ...,verify=False)
+ requests.get("www.google.com", ...,verify=True)
...
import httpx

- httpx.get("www.google.com", ...,verify=False)
+ httpx.get("www.google.com", ...,verify=True)

```

This codemod also checks other methods in the `requests` module and `httpx` library that accept a `verify` flag (e.g. `requests.post`, `httpx.AsyncClient`, etc.)

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

There may be times when setting `verify=False` is useful for testing though we discourage it.
You may also decide to set `verify=/path/to/ca/bundle`. This codemod will not attempt to modify the `verify` value if you do set it to a path.

## Codemod Settings

N/A

## References

- [https://requests.readthedocs.io/en/latest/api/](https://requests.readthedocs.io/en/latest/api/)
- [https://www.python-httpx.org/](https://www.python-httpx.org/)
- [https://owasp.org/www-community/attacks/Manipulator-in-the-middle_attack](https://owasp.org/www-community/attacks/Manipulator-in-the-middle_attack)
