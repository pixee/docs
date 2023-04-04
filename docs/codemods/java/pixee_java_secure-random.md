---
title: Secure Source of Randomness
sidebar_position: 1
---

## pixee:java/secure-random

| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
 | High       | Merge Without Review | No                  |

This codemod replaces all new instances of `java.util.Random` with the marginally slower, but much more secure `java.security.SecureRandom`.

We have to work pretty hard to get computers to generate genuinely unguessable random bits. The `java.util.Random` type uses a method of pseudo-random number generation that unfortunately emits fairly predictable numbers.

If the numbers it emits are predictable, then it's obviously not safe to use in cryptographic operations, file name creation, token construction, password generation, and anything else that's related to security. In fact, it may affect security even if it's not directly obvious.

Switching to a more secure version is simple and the changes look something like this:

```diff
+ import java.security.SecureRandom;
- Random r = new Random();
+ Random r = new SecureRandom();
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this codemod marked as Merge After Cursory Review?

Modern versions of more `SecureRandom` are incredibly fast, and unless you're generating hundreds of megabytes per second of random data, it's unlikely the swap will be noticeably slower. 

## Codemod Settings

N/A

## References
* [https://owasp.org/www-community/vulnerabilities/Insecure_Randomness](https://owasp.org/www-community/vulnerabilities/Insecure_Randomness)
* [https://metebalci.com/blog/everything-about-javas-securerandom/](https://metebalci.com/blog/everything-about-javas-securerandom/)
* [https://cwe.mitre.org/data/definitions/330.html](https://cwe.mitre.org/data/definitions/330.html)