---
title: "Add clarifying braces to misleading code"
sidebar_position: 1
---

## pixee:java/add-clarifying-braces

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| HIGH       | Merge Without Review | No                     |

This change adds clarifying braces to misleading code blocks that look like they may be executing unintended code.

Consider the following code:

```java
if (isAdmin)
  doFirstThing();
  doSecondThing();
```

Although the code formatting makes it look like `doSecondThing()` only executes if `isAdmin` is true, it actually executes regardless of the value of the condition. This pattern of not having curly braces in combination with misaligned indentation leads to security bugs, including the famous [Apple iOS goto fail bug](https://www.synopsys.com/blogs/software-security/understanding-apple-goto-fail-vulnerability-2/) from their SSL library which allowed attackers to intercept and modify encrypted traffic.

This codemod will add braces to control flow statements to make the code more clear, but only in situations in which there is confusing formatting. Our changes look something like this:

```diff
- if (isAdmin)
+ if (isAdmin) {
    doFirstThing();
+ }
    doSecondThing();
```

Note that these changes illuminate situations in which there may be bugs and help make the control flow more clear.

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

The intention of the changes introduced by this codemod is to illuminate situations where they may be bugs and format the code to make it more clear. Therefore, we invite review of this codemod's output not to double check the changed logic, but to see if any bugs have been found.

## References

- [https://cwe.mitre.org/data/definitions/483.html](https://cwe.mitre.org/data/definitions/483.html)
- [https://www.synopsys.com/blogs/software-security/understanding-apple-goto-fail-vulnerability-2/](https://www.synopsys.com/blogs/software-security/understanding-apple-goto-fail-vulnerability-2/)
