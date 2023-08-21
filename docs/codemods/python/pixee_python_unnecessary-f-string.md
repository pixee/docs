---
title: Remove Unnecessary F-string
sidebar_position: 1
---

## pixee:python/remove-unnecessary-f-str

| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
 | Low       | Merge Without Review | No                  |

This codemod converts any f-strings without interpolation to regular strings.

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
* [https://github.com/Instagram/LibCST/blob/main/libcst/codemod/commands/unnecessary_format_string.py](https://github.com/Instagram/LibCST/blob/main/libcst/codemod/commands/unnecessary_format_string.py)
