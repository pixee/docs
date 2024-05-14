---
title: "Replace Deprecated `abc` Decorators"
sidebar_position: 1
---

## pixee:python/fix-deprecated-abstractproperty

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| Low        | Merge Without Review | No                     |

The `@abstractproperty`, `@abstractclassmethod`, and `@abstractstaticmethod` decorators from `abc` has been [deprecated](https://docs.python.org/3/library/abc.html) since Python 3.3. This is because it's possible to use `@property`, `@classmethod`, and `@staticmethod` in combination with `@abstractmethod`.

Our changes look like the following:

```diff
 import abc

 class Foo:
-   @abc.abstractproperty
+   @property
+   @abc.abstractmethod
    def bar():
        ...
```

and similarly for `@abstractclassmethod` and `@abstractstaticmethod`.

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

This change fixes deprecated uses and is safe.

## Codemod Settings

N/A

## References

- [https://docs.python.org/3/library/abc.html#abc.abstractproperty](https://docs.python.org/3/library/abc.html#abc.abstractproperty)
- [https://docs.python.org/3/library/abc.html#abc.abstractclassmethod](https://docs.python.org/3/library/abc.html#abc.abstractclassmethod)
- [https://docs.python.org/3/library/abc.html#abc.abstractstaticmethod](https://docs.python.org/3/library/abc.html#abc.abstractstaticmethod)
