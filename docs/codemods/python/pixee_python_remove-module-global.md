---
title: "Remove `global` Usage at Module Level"
sidebar_position: 1
---

## pixee:python/remove-module-global

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| Low        | Merge Without Review | No                     |

Using the `global` keyword is necessary only when you intend to modify a module-level (aka global) variable within a non-global scope, such as within a class or function. It is unnecessary to call `global` at the module-level.

Our changes look something like this:

```diff
 price = 25
 print("hello")
- global price
 price = 30
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

Since the `global` keyword is intended for use in non-module scopes, using it at the module scope is unnecessary.

## Codemod Settings

N/A

## References

N/A
