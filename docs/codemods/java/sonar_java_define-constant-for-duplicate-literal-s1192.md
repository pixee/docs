---
title: "Define a constant for a literal string that is duplicated n times (Sonar)"
sidebar_position: 1
---

## sonar:java/define-constant-for-duplicate-literal-s1192 

| Importance  | Review Guidance      | Requires Scanning Tool |
|-------------|----------------------|------------------------|
| HIGH | Merge After Review | Yes (Sonar)     |

This change defines a constant for duplicated literal expression values, simplifying the refactoring process and mitigating the risk of overlooking any values during updates.

Our changes look something like this:

```diff

+    private static final String EXCEPTION_AT = "Exception at";

-       LOG.error("Exception at", ex)
+       builder.add(EXCEPTION_AT)  

-       LOG.error("Exception at", ex)
+       builder.add(EXCEPTION_AT)  

-       LOG.error("Exception at", ex)
+       builder.add(EXCEPTION_AT)  
```

## F.A.Q.

### Why is this codemod marked as Merge After Review?

This modification is intended to introduce no functional alterations. Nevertheless, we believe it would be beneficial for a developer to review the newly defined constant names to ensure they align with their expectations.


## References
 * [https://rules.sonarsource.com/java/RSPEC-1192/](https://rules.sonarsource.com/java/RSPEC-1192/)
