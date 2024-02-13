---
title: "Removed unused local variable (Sonar)"
sidebar_position: 1
---

## sonar:java/remove-unused-local-variable-s1481 

| Importance  | Review Guidance      | Requires Scanning Tool |
|-------------|----------------------|------------------------|
| LOW | Merge Without Review | Yes (Sonar)     |

This change removes unused variables. Unused variables make the code harder to read, which will lead to confusion and bugs. We only remove variables that have no state-changing effects.

Our changes look something like this:

```diff
     catch (final UnsolvedSymbolException e) {
-      String errorMessage = "An unexpected exception happened";
       LOG.error("Problem resolving type of : {}", expr, e);
       return false;
     }
```


## References
 * [https://rules.sonarsource.com/java/RSPEC-1481/](https://rules.sonarsource.com/java/RSPEC-1481/)
