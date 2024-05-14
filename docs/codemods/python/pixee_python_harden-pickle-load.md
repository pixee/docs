---
title: "Harden `pickle.load()` against deserialization attacks"
sidebar_position: 1
---

## pixee:python/harden-pickle-load

| Importance | Review Guidance            | Requires Scanning Tool |
| ---------- | -------------------------- | ---------------------- |
| High       | Merge After Cursory Review | No                     |

Python's `pickle` module is notoriouly insecure. While it is very useful for serializing and deserializing Python objects, it is not safe to use `pickle` to load data from untrusted sources. This is because `pickle` can execute arbitrary code when loading data. This can be exploited by an attacker to execute arbitrary code on your system. Unlike `yaml` there is no concept of a "safe" loader in `pickle`. Therefore, it is recommended to avoid `pickle` and to use a different serialization format such as `json` or `yaml` when working with untrusted data.

However, if you must use `pickle` to load data from an untrusted source, we recommend using the open-source `fickling` library. `fickling` is a drop-in replacement for `pickle` that validates the data before loading it and checks for the possibility of code execution. This makes it much safer (although still not entirely safe) to use `pickle` to load data from untrusted sources.

This codemod replaces calls to `pickle.load` with `fickling.load` in Python code. It also adds an import statement for `fickling` if it is not already present.

The changes look like the following:

```diff
- import pickle
+ import fickling

- data = pickle.load(file)
+ data = fickling.load(file)
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

This change may impact performance in some cases, but it is recommended when handling untrusted data.

## Codemod Settings

N/A

## References

- [https://docs.python.org/3/library/pickle.html](https://docs.python.org/3/library/pickle.html)
- [https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
- [https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html#clear-box-review_1](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html#clear-box-review_1)
- [https://github.com/trailofbits/fickling](https://github.com/trailofbits/fickling)
