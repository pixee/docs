---
title: Parameterize SQL Queries
sidebar_position: 1
---

## pixee:python/sql-parameterization

| Importance | Review Guidance            | Requires Scanning Tool |
|------------|----------------------------|------------------------|
| High       | Merge After Cursory Review | No                     |

This codemod refactors SQL statements to be parameterized, rather than built by hand.

Without parameterization, developers must remember to escape string inputs using the rules for that column type and database. This usually results in bugs -- and sometimes vulnerabilities. Although we can't tell for sure if your code is actually exploitable, this change will make the code more robust in case the conditions which prevent exploitation today ever go away.

Our changes look something like this:

```diff
import sqlite3

name = input()
connection = sqlite3.connect("my_db.db")
cursor = connection.cursor()
- cursor.execute("SELECT * from USERS WHERE name ='" + name + "'")
+ cursor.execute("SELECT * from USERS WHERE name =?", (name, ))
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

Python has a wealth of database drivers that all use the same `dbapi2` interface detailed in [PEP249](https://peps.python.org/pep-0249/). Different drivers may require different string tokens used for parameterization, and Python's dynamic typing makes it quite hard, and sometimes impossible, to detect which driver is being used just by looking at the code.

## Codemod Settings

N/A

## References

* [https://cwe.mitre.org/data/definitions/89.html](https://cwe.mitre.org/data/definitions/89.html)
* [https://owasp.org/www-community/attacks/SQL_Injection](https://owasp.org/www-community/attacks/SQL_Injection)
