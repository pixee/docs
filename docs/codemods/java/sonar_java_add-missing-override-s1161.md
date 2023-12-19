---
title: "Sonar: Add Missing @Override Annotation"
sidebar_position: 1
---

## sonar:java/add-missing-override-s1161

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| Low        | Merge Without Review | Yes (Sonar)            |

This codemod adds missing `@Override` annotations to known subclass methods. Documenting inheritance will help readers and static analysis tools understand the code better, spot bugs easier, and in general lead to more efficient and effective review.

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

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

There is no functional difference after the change, but the source code will be easier to understand.

## Codemod Settings

N/A

## References

* [https://rules.sonarsource.com/java/RSPEC-1161/](https://rules.sonarsource.com/java/RSPEC-1161/)