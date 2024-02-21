---
title: "Automatically Close Resources"
sidebar_position: 1
---

## pixee:python/fix-file-resource-leak

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| High       | Merge Without Review | No                     |

This codemod wraps assignments of `open` calls in a with statement. Without explicit closing, these resources will be "leaked" and won't be re-claimed until garbage collection. In situations where these resources are leaked rapidly (either through malicious repetitive action or unusually spiky usage), connection pool or file handle exhaustion will occur. These types of failures tend to be catastrophic, resulting in downtime and many times affect downstream applications.

Our changes look something like this:

```diff
import tempfile
path = tempfile.NamedTemporaryFile().name
-file = open(path, 'w', encoding='utf-8')
-file.write('Hello World')
+with open(path, 'w', encoding='utf-8') as file:
+   file.write('Hello World')
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

We believe this change is safe and will only close file resources that are not referenced outside of the with statement block.

## Codemod Settings

N/A

## References

* [https://cwe.mitre.org/data/definitions/772.html](https://cwe.mitre.org/data/definitions/772.html)
* [https://cwe.mitre.org/data/definitions/404.html](https://cwe.mitre.org/data/definitions/404.html)
