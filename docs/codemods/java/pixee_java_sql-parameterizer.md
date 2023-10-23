---
title: Switch to Parameterized SQL APIs
sidebar_position: 1
---

## pixee:java/sql-parameterizer

| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
 | High       | Merge Without Review | No                  |

This codemod refactors SQL statements to be parameterized, rather than built by hand.

Without parameterization, developers must remember to escape string inputs using the rules for that column type and database. This usually results in bugs -- and sometimes vulnerability. Although it's not clear if this code is exploitable today, this change will make the code more robust in case the conditions which prevent exploitation today ever go away. 

Our changes look something like this:

```diff
- Statement stmt = connection.createStatement();
- ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
+ PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE name = ?");
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
* [https://owasp.org/www-community/attacks/SQL_Injection](https://owasp.org/www-community/attacks/SQL_Injection)
* [https://cwe.mitre.org/data/definitions/89.html](https://cwe.mitre.org/data/definitions/89.html)
