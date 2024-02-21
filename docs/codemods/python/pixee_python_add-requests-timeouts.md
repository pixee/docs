---
title: "Add timeout to `requests` calls"
sidebar_position: 1
---

## pixee:python/add-requests-timeouts

| Importance | Review Guidance            | Requires Scanning Tool |
|------------|----------------------------|------------------------|
| Medium     | Merge After Cursory Review | No                     |

Many developers will be surprised to learn that `requests` library calls do not include timeouts by default. This means that an attempted request could hang indefinitely if no connection is established or if no data is received from the server. 

The [requests documentation](https://requests.readthedocs.io/en/latest/user/advanced/#timeouts) suggests that most calls should explicitly include a `timeout` parameter. This codemod adds a default timeout value in order to set an upper bound on connection times and ensure that requests connect or fail in a timely manner. This value also ensures the connection will timeout if the server does not respond with data within a reasonable amount of time. 

While timeout values will be application dependent, we believe that this codemod adds a reasonable default that serves as an appropriate ceiling for most situations. 

Our changes look like the following:
```diff
 import requests
 
- requests.get("http://example.com")
+ requests.get("http://example.com", timeout=60)
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

This change makes your code safer but in some cases it may be necessary to adjust the timeout value for your particular application.

## Codemod Settings

N/A

## References

* [https://docs.python-requests.org/en/master/user/quickstart/#timeouts](https://docs.python-requests.org/en/master/user/quickstart/#timeouts)
