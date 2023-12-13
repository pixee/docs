---
title: Remove Unnecessary F-strings
sidebar_position: 1
---

## pixee:python/remove-unnecessary-f-str

| Importance | Review Guidance            | Requires SARIF Tool |
|------------|----------------------------|---------------------|
| Low       | Merge Without Review | No                  |

This codemod converts any f-strings without interpolated variables into regular strings.
In these cases the use of f-string is not necessary; a simple string literal is sufficient. 

While in some (extreme) cases we might expect a very modest performance
improvement, in general this is a fix that improves the overall cleanliness and
quality of your code.

```diff
- var = f"hello"
+ var = "hello"
  ...
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

We believe this codemod is safe and will not cause any issues.

## Codemod Settings

N/A

## References

* [https://pylint.readthedocs.io/en/latest/user_guide/messages/warning/f-string-without-interpolation.html](https://pylint.readthedocs.io/en/latest/user_guide/messages/warning/f-string-without-interpolation.html)
* [https://github.com/Instagram/LibCST/blob/main/libcst/codemod/commands/unnecessary_format_string.py](https://github.com/Instagram/LibCST/blob/main/libcst/codemod/commands/unnecessary_format_string.py)
