---
title: "Removed block of commented-out lines of code (Sonar)"
sidebar_position: 1
---

## sonar:java/remove-commented-code-s125 

| Importance  | Review Guidance      | Requires Scanning Tool |
|-------------|----------------------|------------------------|
| HIGH | Merge Without Review | Yes (Sonar)     |

This change eliminates commented-out code that may impede readability and distract focus. Any deleted code can still be accessed through the source control history if needed.

Our changes look something like this:

```diff
   catch (IOException e) { 
-    // LOG.error("Unexpected problem ", ex);
     return handleError(ex);
   }
```


## References
 * [https://rules.sonarsource.com/java/RSPEC-125/](https://rules.sonarsource.com/java/RSPEC-125/)
