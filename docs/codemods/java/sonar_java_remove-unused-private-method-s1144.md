---
title: "Removed unused private method (Sonar)"
sidebar_position: 1
---

## sonar:java/remove-unused-private-method-s1144 

| Importance  | Review Guidance      | Requires Scanning Tool |
|-------------|----------------------|------------------------|
| HIGH | Merge After Review | Yes (Sonar)     |

This change removes unused `private` methods. Dead code can cause confusion and increase the mental load of maintainers. It can increase your maintenance burden as you have to keep that unused code compiling when you make sweeping changes to the APIs used within the method.

Our changes look something like this:

```diff
-   private String getUuid(){
-       return uuid;
-   }
```


## References
 * [https://rules.sonarsource.com/java/RSPEC-1144/](https://rules.sonarsource.com/java/RSPEC-1144/)
 * [https://understandlegacycode.com/blog/delete-unused-code/](https://understandlegacycode.com/blog/delete-unused-code/)
