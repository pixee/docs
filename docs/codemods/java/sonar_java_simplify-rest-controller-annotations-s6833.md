---
title: "Sonar: Migrate @Controller/@ResponseBody to @RestController"
sidebar_position: 1
---

## sonar:java/simplify-rest-controller-annotations-s6833

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| Low        | Merge Without Review | Yes (Sonar)            |

This codemod makes it harder for developers to make a mistake when writing REST controllers in Spring. By marking the top level type with `@RestController`, it is now assumed that all the methods within it will return a Java object representing the response body. Thus, there is no need to specify, for each method, the `@ResponseBody` annotation.

Our changes look something like this:

```diff
-   import org.springframework.stereotype.Controller;
-   import org.springframework.web.bind.annotation.ResponseBody;
+   import org.springframework.web.bind.annotation.RestController;
-   @Controller
+   @RestController
    public class AccountController {
      ...
-     @ResponseBody
      public AccountDetails viewAccount() {
        ...
```


If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

There are no functional changes after this change, but the code will be easier to understand.

## Codemod Settings

N/A

## References

* [https://rules.sonarsource.com/java/RSPEC-6833/](https://rules.sonarsource.com/java/RSPEC-6833/)