---
title: "Use `shell=False` in `subprocess` Function Calls"
sidebar_position: 1
---

## pixee:python/subprocess-shell-false

| Importance | Review Guidance            | Requires Scanning Tool |
| ---------- | -------------------------- | ---------------------- |
| High       | Merge After Cursory Review | No                     |

This codemod sets the `shell` keyword argument to `False` in `subprocess` module function calls that have set it to `True`.

Setting `shell=True` will execute the provided command through the system shell which can lead to shell injection vulnerabilities. In the worst case this can give an attacker the ability to run arbitrary commands on your system. In most cases using `shell=False` is sufficient and leads to much safer code.

The changes from this codemod look like this:

```diff
 import subprocess
- subprocess.run("echo 'hi'", shell=True)
+ subprocess.run("echo 'hi'", shell=False)
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

In most cases setting `shell=False` is correct and leads to much safer code. However there are valid use cases for `shell=True` when using shell functionality like pipes or wildcard is required. In such cases it is important to run only trusted, validated commands.

## Codemod Settings

N/A

## References

- [https://docs.python.org/3/library/subprocess.html#security-considerations](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [https://en.wikipedia.org/wiki/Code_injection#Shell_injection](https://en.wikipedia.org/wiki/Code_injection#Shell_injection)
- [https://stackoverflow.com/a/3172488](https://stackoverflow.com/a/3172488)
