---
title: "Sonar: Removed block of commented-out lines of code"
sidebar_position: 1
---

## sonar:java/remove-commented-code-s125

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| Low        | Merge Without Review | Yes (Sonar)            |

TODO

Our changes look like this:

```diff

-   // LOG.error("Unexpected problem ", ex);
+   

```


If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

There is no functional difference after the change, but the source code will be easier to understand.

## Codemod Settings

N/A

## References

* [https://rules.sonarsource.com/java/RSPEC-125/](https://rules.sonarsource.com/java/RSPEC-125/)