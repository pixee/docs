---
title: Secure Hash Algorithm
sidebar_position: 1
---

## pixee:python/insecure-hash

| Importance | Review Guidance            | Requires SARIF Tool |
|------------|----------------------------|---------------------|
| High       | Merge After Cursory Review | No                  |

This codemod converts any calls to `hashlib.md5` or `hashlib.sha1` to `hashlib.sha256`. Md5 and sha1 are hashing algorithms
prone to collision attacks so they should be avoided.

```diff
import hashlib
- hashlib.md5(b"1").hexdigest()
- hashlib.sha1(b"1").hexdigest()
+ hashlib.sha256(b"1").hexdigest()
+ hashlib.sha256(b"1").hexdigest()
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this codemod marked as Merge After Cursory Review ?

We believe this codemod is safe and will not cause any issues. Sha256 is a reasonable replacement but some may want to choose a different algorithm.

## Codemod Settings

N/A

## References
* [https://docs.python.org/3/library/hashlib.html#hash-algorithms](https://docs.python.org/3/library/hashlib.html#hash-algorithms)
* [https://www.schneier.com/blog/archives/2012/10/when_will_we_se.html](https://www.schneier.com/blog/archives/2012/10/when_will_we_se.html)
* [http://2012.sharcs.org/slides/stevens.pdf](http://2012.sharcs.org/slides/stevens.pdf)
