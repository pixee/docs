---
title: "Refactored to use parameterized HQL APIs"
sidebar_position: 1
---

## pixee:java/hql-parameterizer

| Importance | Review Guidance    | Requires Scanning Tool |
| ---------- | ------------------ | ---------------------- |
| HIGH       | Merge After Review | No                     |

This change refactors Hibernate queries to be parameterized, rather than built by hand.

Without parameterization, developers must remember to escape inputs using the rules for that database. It's usually buggy, at the least -- and sometimes vulnerable.

Our changes look something like this:

```diff
- Query<User> hqlQuery = session.createQuery("select p from Person p where p.name like '" + tainted + "'");
+ Query<User> hqlQuery = session.createQuery("select p from Person p where p.name like :parameter0").setParameter(":parameter0", tainted);
```

## F.A.Q.

### Why is this codemod marked as Merge After Review?

Although there should be no functional differences, the rewrite here is complex and should be verified by a human.

## References

- [https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html#using-java-with-hibernate](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html#using-java-with-hibernate)
- [https://cwe.mitre.org/data/definitions/564.html](https://cwe.mitre.org/data/definitions/564.html)
