---
title: Move Switch Default Case to Last
sidebar_position: 1
---

## pixee:java/move-switch-default-last

| Importance | Review Guidance            | Requires SARIF Tool |
|------------|----------------------------|---------------------|
| Low        | Merge After Cursory Review | No                  |

This codemod moves the `default` case of `switch` statements to the end to match convention.

If code is hard to read, it is by definition hard to reason about. This is true not only during review, but also while coding in that area later. Not being able to quickly and effectively reason about code will lead to bugs, including security vulnerabilities.

The `default` case is usually last. Being further up may cause confusion about how the code will flow as is shown in the example below, which will perhaps unexpected grant access when there shouldn't be:

```java
  switch (accessLevel) {
   default:
     access = false;
   case GRANTED:
     access = true;
     break;
   case REJECTED:
     access = false;
     break;
  }
```

To avoid any confusion about how the code flows, we move the `default` case to the end. Our changes look something like this:

```diff
  switch (accessLevel) {
-    default:
-      access = false;
     case GRANTED:
       access = true;
       break;
     case REJECTED:
       access = false;
       break;
+    default:
+      access = false;
  }
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

There should be no difference to code flow if the `default` case is moved except in cases where there is likely an existing bug, with which this will help surface.

## References
 * [https://cwe.mitre.org/data/definitions/670.html](https://cwe.mitre.org/data/definitions/670.html)
 * [https://pmd.github.io/pmd/pmd_rules_java_bestpractices.html#defaultlabelnotlastinswitchstmt](https://pmd.github.io/pmd/pmd_rules_java_bestpractices.html#defaultlabelnotlastinswitchstmt)
 * [https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/switch](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/switch)
