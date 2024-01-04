---
title: Verbose Request Mapping
sidebar_position: 1
---

## pixee:java/verbose-request-mapping

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| Normal     | Merge Without Review | No                     |

This codemod simplifies Spring Framework annotations by making use of shortened annotations when applicable.
Code that is easy to read is easy to review, reason about, and detect bugs in.

Making use of shortcut annotations accomplishes this by removing *wordy for no reason* elements.  


Version 4.3 of Spring Framework introduced method-level variants for `@RequestMapping`.
- `@GetMapping`
- `@PutMapping`
- `@PostMapping`
- `@DeleteMapping`
- `@PatchMapping`

```diff
- @RequestMapping(value = "/example", method = RequestMethod.GET)
  ...
+ @GetMapping(value = "/example")
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this codemod marked as Merge Without Review?

There is no reason an application should be forwarding to inner resources like `/WEB-INF/web.xml`, 

## Codemod Settings

N/A

## References

* [https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-requestmapping.html](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-requestmapping.html)
* [https://dzone.com/articles/using-the-spring-requestmapping-annotation](https://dzone.com/articles/using-the-spring-requestmapping-annotation)
