---
title: "Sonar: Remove unused local variable"
sidebar_position: 1
---

## sonar:java/remove-unused-local-variable-s1481

| Importance | Review Guidance            | Requires Scanning Tool |
|------------|----------------------------|------------------------|
| Low        | Merge After Cursory Review | Yes (Sonar)            |

This codemod removes unused variables. Unused variables make the code harder to read, which will lead to confusion and bugs. We only remove variables that have no state-changing effects.

Our changes look something like this:

```diff
     catch (final UnsolvedSymbolException e) {
-      String errorMessage = "An unexpected exception happened";
       LOG.error("Problem resolving type of : {}", expr, e);
       return false;
     }
```


If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

There should be no functional changes after this change as we double check to ensure that the variables . However, we think it may be valuable for a developer to see the change being made and see if it alters their understanding of the code, and if the deletion of the unused variable makes obvious the appearance of any functional bugs. 

## Codemod Settings

N/A

## References

* [https://rules.sonarsource.com/java/RSPEC-1481/](https://rules.sonarsource.com/java/RSPEC-1481/)