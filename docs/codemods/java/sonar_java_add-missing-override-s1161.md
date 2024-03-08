---
title: "Added missing @Override parameter (Sonar)"
sidebar_position: 1
---

## sonar:java/add-missing-override-s1161

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| LOW        | Merge Without Review | Yes (Sonar)            |

This change adds missing `@Override` to known subclasses. Documenting inheritance will help readers and static analysis tools understand the code better, spot bugs easier, and in general lead to more efficient and effective review.

Our changes look something like this:

```diff
  interface AcmeParent {
     void doThing();
  }

  class AcmeChild implements AcmeParent {

+   @Override
    void doThing() {
      thing();
    }

  }
```

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

There is no functional difference after the change, but the source code will be easier to understand.

## References

- [https://rules.sonarsource.com/java/RSPEC-1161/](https://rules.sonarsource.com/java/RSPEC-1161/)
