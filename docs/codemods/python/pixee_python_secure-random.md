---
title: Secure Source of Randomness
sidebar_position: 1
---

## pixee:python/secure-random

| Importance | Review Guidance            | Requires SARIF Tool |
|------------|----------------------------|---------------------|
 | High       | Merge After Cursory Review | No                  |

This codemod replaces all new instances of `random.random()` with the much more secure `secrets.SystemRandom().uniform(0, 1)`.

There is significant algorithmic complexity in getting computers to generate genuinely unguessable random bits. The `random.random()` function uses a method of pseudo-random number generation that unfortunately emits fairly predictable numbers.

If the numbers it emits are predictable, then it's obviously not safe to use in cryptographic operations, file name creation, token construction, password generation, and anything else that's related to security. In fact, it may affect security even if it's not directly obvious.

Switching to a more secure version is simple and the changes look something like this:

```diff
- import random
+ import secrets
  ...
- random.random()
+ gen = secrets.SystemRandom()
+ gen.uniform(0, 1)
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this codemod marked as Merge After Cursory?? Review?

While most of the functions in the `random` module aren't cryptographically secure, there are still valid use cases for
`random.random()` such as for simulations or games.


## Codemod Settings

N/A

## References
* [https://owasp.org/www-community/vulnerabilities/Insecure_Randomness](https://owasp.org/www-community/vulnerabilities/Insecure_Randomness)
* [https://docs.python.org/3/library/random.html](https://docs.python.org/3/library/random.html)
