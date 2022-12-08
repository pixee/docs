---
title: "Fix Verb Tampering"
sidebar_position: 1
---

## pixee:java/fix-verb-tampering

| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
 | High       | Merge Without Review | No                  |

The `web.xml` specification offers a way to protect certain parts of your URL space. Unfortunately, it doesn't work the way people think it does, developers who are trying to enhance their security often end up accidentally exposing those parts they were trying to protect.

Consider the following `web.xml`, which is trying to restrict the `/admin/*` space to only those with the `admin` role:
```xml
<security-constraint>
  <web-resource-collection>
    <url-pattern>/admin/*</url-pattern>
    <http-method>GET</http-method>
    <http-method>POST</http-method>
  </web-resource-collection>
  <auth-constraint>
    <role-name>admin</role-name>
  </auth-constraint>
</security-constraint>
```

This protection works as expected with one regrettable caveat. Notice that the `GET` and `POST` methods are specifically listed. Developers often specify methods like this because they want to further control what types of methods can access the given resource.

Unfortunately, the logic of the mechanism is surprising. Specifying method(s) means if a user issues another HTTP method besides the ones listed, like in this case, `HEAD`, `PUT`, or even a nonsense verb like `JEFF`, the protection will not be deemed to apply to the given `<security-constraint>`, and the requester will be granted unfettered access. 

This confusion results in a shockingly high percentage of these configurations being vulnerable to complete bypass. Even the application servers' own software has fallen [victim to it](https://blog.mindedsecurity.com/2010/04/good-bye-critical-jboss-0day.html). 

Our change is simple: any place we see `<http-method>` listed in a `<security-constraint>`, we remove it:

```diff
<security-constraint>
  <auth-constraint>
    <role-name>admin</role-name>
  </auth-constraint>
  <web-resource-collection>
    <url-pattern>/admin/*</url-pattern>
-   <http-method>GET</http-method>
-   <http-method>POST</http-method>
  </web-resource-collection>
</security-constraint>
```

Taking out all the `<http-method>` entries tells the server that this protection must be enforced for all methods, which is almost always the intent of the developer.

If you have feedback on this rule, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this rule marked as Merge Without Review?

This is an incredibly unintuitive situation and in our professional experience have never seen any ttime developers intended to grant access to "all other" HTTP methods by specifically listing others. 

## Rule Settings

N/A

## References
* [https://dl.packetstormsecurity.net/papers/web/Bypassing_VBAAC_with_HTTP_Verb_Tampering.pdf](https://dl.packetstormsecurity.net/papers/web/Bypassing_VBAAC_with_HTTP_Verb_Tampering.pdf)
* [https://blog.mindedsecurity.com/2010/04/good-bye-critical-jboss-0day.html](https://blog.mindedsecurity.com/2010/04/good-bye-critical-jboss-0day.html)
* [https://vulncat.fortify.com/en/detail?id=desc.config.java.http_verb_tampering](https://vulncat.fortify.com/en/detail?id=desc.config.java.http_verb_tampering)
* [https://capec.mitre.org/data/definitions/274.html](https://capec.mitre.org/data/definitions/274.html)
