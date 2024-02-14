---
title: "Refactored to use parameterized SQL APIs"
sidebar_position: 1
---

## pixee:java/sql-parameterizer 

| Importance  | Review Guidance      | Requires Scanning Tool |
|-------------|----------------------|------------------------|
| HIGH | Merge After Review | No     |

This change refactors SQL statements to be parameterized, rather than built by hand.

Without parameterization, developers must remember to escape inputs using the rules for that database. It's usually buggy, at the least -- and sometimes vulnerable.

Our changes look something like this:

```diff
- Statement stmt = connection.createStatement();
- ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
+ PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE name = ?");
+ stmt.setString(1, user);
+ ResultSet rs = stmt.executeQuery();
```

## F.A.Q.

### Why is this codemod marked as Merge After Review?

Although there should be no functional differences, the rewrite here is complex and should be verified by a human.


## References
 * [https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
 * [https://cwe.mitre.org/data/definitions/89.html](https://cwe.mitre.org/data/definitions/89.html)
