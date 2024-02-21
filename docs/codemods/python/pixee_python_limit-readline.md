---
title: "Limit readline()"
sidebar_position: 1
---

## pixee:python/limit-readline

| Importance | Review Guidance            | Requires Scanning Tool |
|------------|----------------------------|------------------------|
| Medium     | Merge After Cursory Review | No                     |

This codemod hardens all [`readline()`](https://docs.python.org/3/library/io.html#io.IOBase.readline) calls from file objects returned from an `open()` call, `StringIO` and `BytesIO` against denial of service attacks. A stream influenced by an attacker could keep providing bytes until the system runs out of memory, causing a crash.

Fixing it is straightforward by providing adding a size argument to any `readline()` calls.
The changes from this codemod look like this:

```diff
  file = open('some_file.txt')
- file.readline()
+ file.readline(5_000_000)
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

This codemod sets a maximum of 5MB allowed per line read by default. It is unlikely but possible that your code may receive lines that are greater than 5MB _and_ you'd still be interested in reading them, so there is some nominal risk of exceptional cases.

## Codemod Settings

N/A

## References

* [https://cwe.mitre.org/data/definitions/400.html](https://cwe.mitre.org/data/definitions/400.html)
