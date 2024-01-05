---
title: "Sonar: Remove unused private method"
sidebar_position: 1
---

## sonar:java/remove-unused-private-method-s1144

| Importance | Review Guidance            | Requires Scanning Tool |
|------------|----------------------------|------------------------|
| High       | Merge After Review         | Yes (Sonar)            |

This codemod removes unused `private` methods. Dead code can cause confusion and increase the mental load of maintainers. It can increase your maintenance burden as you have to keep that unused code compiling when you make sweeping changes to the APIs used within the method.

Our changes look something like this:

```diff
-   private String getUuid(){
-       return uuid;
-   }
```


If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

There should be no functional changes after this change. However, we think it may be valuable for a developer to see the change being made and see if it alters their understanding of the code. 

## Codemod Settings

N/A

## References

* [https://rules.sonarsource.com/java/RSPEC-1144/](https://rules.sonarsource.com/java/RSPEC-1144/)
* [https://understandlegacycode.com/blog/delete-unused-code/](https://understandlegacycode.com/blog/delete-unused-code/)