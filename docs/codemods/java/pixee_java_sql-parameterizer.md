---
title: Switch to Parameterized SQL APIs
sidebar_position: 1
---

## pixee:java/sql-parameterizer

| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
 | High       | Merge Without Review | No                  |

This codemod refactors SQL statements to be parameterized, rather than built by hand.

Without parameterization, developers must remember to escape string inputs using the rules for that column type and database. This usually results in bugs -- and sometimes vulnerability. This 

Our changes look something like this:

```diff
- Statement stmt = connection.createStatement();
- ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
+ PreparedStatement stmt = connection.prepareStatement();
+ stmt.setString(1, user);
+ ResultSet rs = stmt.executeQuery();
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this codemod marked as Merge Without Review

The codemod is thoroughly tested to only handle a guaranteed safe set of conditions.

## Codemod Settings

N/A

## References
* [https://owasp.org/www-community/vulnerabilities/Insecure_Randomness](https://owasp.org/www-community/vulnerabilities/Insecure_Randomness)
* [https://metebalci.com/blog/everything-about-javas-securerandom/](https://metebalci.com/blog/everything-about-javas-securerandom/)
* [https://cwe.mitre.org/data/definitions/330.html](https://cwe.mitre.org/data/definitions/330.html)
