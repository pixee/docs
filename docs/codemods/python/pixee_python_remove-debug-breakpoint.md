---
title: "Remove Calls to `builtin` `breakpoint` and `pdb.set_trace"
sidebar_position: 1
---

## pixee:python/remove-debug-breakpoint

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| Medium     | Merge Without Review | No                     |

This codemod removes any calls to `breakpoint()` or `pdb.set_trace()` which are generally only used for interactive debugging and should not be deployed in production code.

In most cases if these calls are included in committed code, they were left there by mistake and indicate a potential problem.

```diff
 print("hello")
- breakpoint()
 print("world")
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

Breakpoints are generally used only for debugging and can easily be forgotten before deploying code.

## Codemod Settings

N/A

## References

N/A
