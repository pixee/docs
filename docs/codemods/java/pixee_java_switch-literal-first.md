---
title: Switch Order of Literals
sidebar_position: 1
---

## pixee:java/switch-literal-first

| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
| Low        | Merge Without Review | No                  |



If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

There should be no difference to code flow if the literal is first except in cases where the behavior is now fixed where a bug previously existed.

## References

"http://cwe.mitre.org/data/definitions/476.html",
"https://en.wikibooks.org/wiki/Java_Programming/Preventing_NullPointerException",
"https://rules.sonarsource.com/java/RSPEC-1132/"
