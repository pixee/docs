---
title: "Sonar: Added missing synchronized keyword"
sidebar_position: 1
---

## sonar:java/overrides-match-synchronization-s3551

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| Medium     | Merge Without Review | Yes (Sonar)            |

This codemod adds missing `synchronized` keyword to known subclass methods that override a method that is marked specified as synchronized.

Our changes look something like this:

```diff
  interface AcmeParent {
     synchronized void doThing();
  } 

  class AcmeChild implements AcmeParent {

    @Override
-    void doThing() {
+    public synchronized void doThing() {
      thing();
    }
  }
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Are there other ways to implement this?
There are a number of different ways to fix this, but essentially we need to make this code thread-safe. This is important when the parent interface implies something is synchronized, signaling an expectation of thread-safety, when an implementation is not.

## Codemod Settings

N/A

## References

* [https://rules.sonarsource.com/java/RSPEC-3551/](https://rules.sonarsource.com/java/RSPEC-3551/)
* [https://wiki.sei.cmu.edu/confluence/display/java/TSM00-J.+Do+not+override+thread-safe+methods+with+methods+that+are+not+thread-safe](https://wiki.sei.cmu.edu/confluence/display/java/TSM00-J.+Do+not+override+thread-safe+methods+with+methods+that+are+not+thread-safe)
