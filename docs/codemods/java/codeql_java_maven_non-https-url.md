---
title: "Failure to use HTTPS or SFTP URL in Maven artifact upload/download (CodeQL)"
sidebar_position: 1
---

## codeql:java/maven/non-https-url

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| MEDIUM     | Merge Without Review | Yes (CodeQL)           |

This change replaces any HTTP URLs found in `<repository>` definitions with HTTPS URLs. Without this change, Maven will make requests to either publish or retrieve artifacts over a plaintext channel.

That plaintext channel can be [observed or modified by malicious actors](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) on the network path between the host running Maven and their intended repository. These actors could then sniff repository credentials, publish malicious artifacts, etc. Simply switching to an HTTPS URL is sufficient to make all of these attacks impossible in almost all situations.

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

## References

- [https://codeql.github.com/codeql-query-help/java/java-maven-non-https-url](https://codeql.github.com/codeql-query-help/java/java-maven-non-https-url)
- [https://cwe.mitre.org/data/definitions/494.html](https://cwe.mitre.org/data/definitions/494.html)
- [https://en.wikipedia.org/wiki/Man-in-the-middle_attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack)
