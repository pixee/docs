---
title: "Removed redundant static flag on enum (Sonar)"
sidebar_position: 1
---

## sonar:java/remove-redundant-static-s2786

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| LOW        | Merge Without Review | Yes (Sonar)            |

This change removes redundant (and possibly misleading) `static` keywords on `enum` types defined within classes. All `enum` types that are nested within another type are automatically `static`, and so listing the flag this clutters the code, and may cause confusion when reasoning about it.

Our changes look something like this:

```diff
  @RestController
  final class CheckStatusController {

-   static enum ResponseType {
+   enum ResponseType {
      SUCCESS,
      FAILURE,
      ERROR
    }
```

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

There are no functional changes after this change, but the code will be easier to understand.

## References

- [https://sonarsource.github.io/rspec/#/rspec/S2786/java](https://sonarsource.github.io/rspec/#/rspec/S2786/java)
