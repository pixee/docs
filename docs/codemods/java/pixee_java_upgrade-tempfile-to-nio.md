---
title: Modernize and Secure Temp File Creation 
sidebar_position: 1
---

## pixee:java/upgrade-tempfile-to-nio

| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
| Medium     | Merge Without Review | No                  |

This codemod replaces the usage of [`java.io.File#createTempFile`](https://docs.oracle.com/en/java/javase/20/docs/api/java.base/java/io/File.html#createTempFile(java.lang.String,java.lang.String)) with [`java.nio.file.Files#createTempFile`](https://docs.oracle.com/en/java/javase/20/docs/api/java.base/java/nio/file/Files.html#createTempFile(java.lang.String,java.lang.String,java.nio.file.attribute.FileAttribute...)) which has more secure attributes.

The `java.io.File#createTempFile()` method creates a file that is world-readable and world-writeable, which is almost never necessary. Also, the file created is placed in a predictable directory (e.g., `/tmp`). Having predictable file names, locations, and will lead to many types of vulnerabilities. History has shown that this insecure pattern can lead to [information leakage](https://www.cvedetails.com/cve/CVE-2021-28168/), [privilege escalation](https://www.cvedetails.com/cve/CVE-2021-29428/) and even [code execution](https://www.openwall.com/lists/oss-security/2022/02/25/3).

Our changes look something like this:

```diff
+  import java.nio.file.Files;
-  File txtFile = File.createTempFile("acme", ".txt");
+  File txtFile = Files.createTempFile("acme", ".txt").toFile();
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

Unless the temporary files created by this code are intended to be read and edited by other applications on the system, and are intended to be in a predictable directory, this change should be merged. It's difficult to conceive of a situation where this would be by design and these changes would cause an issue.

## References
* [https://cwe.mitre.org/data/definitions/378.html](https://cwe.mitre.org/data/definitions/378.html)
* [https://docs.fluidattacks.com/criteria/vulnerabilities/160/](https://docs.fluidattacks.com/criteria/vulnerabilities/160/)
* [https://github.com/apache/druid/issues/11130](https://github.com/apache/druid/issues/11130)
* [https://owasp.org/www-community/vulnerabilities/Insecure_Temporary_File](https://owasp.org/www-community/vulnerabilities/Insecure_Temporary_File)
* [https://nvd.nist.gov/vuln/detail/CVE-2022-41954](https://nvd.nist.gov/vuln/detail/CVE-2022-41954)
* [https://www.cvedetails.com/vulnerability-list/cwe-378/vulnerabilities.html](https://www.cvedetails.com/vulnerability-list/cwe-378/vulnerabilities.html)
