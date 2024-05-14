---
title: "Add Missing Positional Parameter for Instance and Class Methods"
sidebar_position: 1
---

## pixee:python/fix-missing-self-or-cls

| Importance | Review Guidance            | Requires Scanning Tool |
| ---------- | -------------------------- | ---------------------- |
| Low        | Merge After Cursory Review | No                     |

Python instance methods must be defined with `self` as the first argument. Likewise, class methods must have `cls` as the first argument. This codemod will add these arguments when the method/class method has no arguments defined.

Our changes look something like this:

```diff
 class MyClass:
-    def instance_method():
+    def instance_method(self):
         print("instance_method")

     @classmethod
-    def class_method():
+    def class_method(cls):
         print("class_method")
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

This change is safe and will prevent errors when calling on these instance or class methods..

## Codemod Settings

N/A

## References

N/A
