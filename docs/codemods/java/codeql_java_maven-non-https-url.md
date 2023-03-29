---
title: "CodeQL: Expression language injection (JEXL)"
sidebar_position: 1
---

## codeql:java/maven-non-https-url 

| Importance | Review Guidance            | Requires SARIF Tool |
|------------|----------------------------|---------------------|
| Medium     | Merge After Cursory Review | Yes (CodeQL)        |

This codemod replaces any HTTP URLs found in `<repository>` definitions with HTTPS URLs. Without this change, Maven will make requests to either publish or retrieve artifacts over a plaintext channel. 

That plaintext channel can be observed or modified by malicious actors on the network path between the host running Maven and their intended repository. These actors could then sniff repository credentials, publish malicious artifacts, etc. Simply switching to an HTTPS URL is sufficient to make all of these attacks impossible in almost all situations.

Our changes look something like this:

```diff
  <?xml version="1.0" encoding="UTF-8"?>
  <project xmlns="http://maven.apache.org/POM/4.0.0" ...>
    ...
    <distributionManagement>
      <repository>
        <id>my-release-repo</id>
        <name>Acme Releases</name>
-       <url>http://repo.acme.com</url>
+       <url>https://repo.acme.com</url>
      </repository>
    </distributionManagement>
  </project>
```

## F.A.Q.

### Why is this codemod marked as Merge After Cursory Review?

This codemod replaces URLs to repositories that are insecure. Most repositories, including from the most popular services, are available through HTTPS. Some may even attempt to force HTTPS by redirection, though that would still be vulnerable to man-in-the-middle attacks because the initial request could be intercepted. The only realistic chance for this causing issues is if users are referencing an internal repository that wasn't setup to also serve HTTPS. This seems unlikely, but it may be worth checking before making this change permanent.  

## Codemod Settings

N/A

## References
* [https://codeql.github.com/codeql-query-help/java/jexl-expression-injection/](https://codeql.github.com/codeql-query-help/java/java-database-resource-leak/)
* [https://commons.apache.org/proper/commons-jexl/apidocs/org/apache/commons/jexl3/introspection/JexlSandbox.html](https://commons.apache.org/proper/commons-jexl/apidocs/org/apache/commons/jexl3/introspection/JexlSandbox.html)
* [https://cwe.mitre.org/data/definitions/693.html](https://cwe.mitre.org/data/definitions/693.html)
* [https://cwe.mitre.org/data/definitions/94.html](https://cwe.mitre.org/data/definitions/94.html)
