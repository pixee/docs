---
title: "Remove redundant variable creation expression when it is only returned/thrown (Sonar)"
sidebar_position: 1
---

## sonar:java/remove-redundant-variable-creation-s1488

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| LOW        | Merge Without Review | Yes (Sonar)            |

This change removes intermediate variables who are only created to be thrown or returned in the next statement. This makes the code more readable, which makes reviewing the code for issues easier.

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

## References

- [https://rules.sonarsource.com/java/RSPEC-1488/](https://rules.sonarsource.com/java/RSPEC-1488/)
