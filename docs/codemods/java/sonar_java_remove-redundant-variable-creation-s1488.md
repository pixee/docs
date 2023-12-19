---
title: "Sonar: Remove redundant variable creation expression when it is only returned/thrown"
sidebar_position: 1
---

## sonar:java/remove-redundant-variable-creation-s1488

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| Low        | Merge Without Review | Yes (Sonar)            |

This codemod removes intermediate variables who are only created to be thrown or returned in the next statement. This makes the code more readable, which makes reviewing the code for issues easier.

Our changes look something like this:

```diff
    public LocaleResolver localeResolver() { 
-       SessionLocaleResolver localeResolver = new SessionLocaleResolver();
-       return localeResolver;
+       return new SessionLocaleResolver();
    }
```

```diff
    public void process() { 
-       Exception ex = new Exception();
-       throw ex;
+       throw new Exception();
    }
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

There are no functional changes after this change, but the code will be easier to understand.

## Codemod Settings

N/A

## References

* [https://rules.sonarsource.com/java/RSPEC-1488/](https://rules.sonarsource.com/java/RSPEC-1488/)