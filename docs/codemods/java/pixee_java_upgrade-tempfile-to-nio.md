---
title: "Modernize and secure temp file creation"
sidebar_position: 1
---

## pixee:java/upgrade-tempfile-to-nio 

| Importance  | Review Guidance      | Requires Scanning Tool |
|-------------|----------------------|------------------------|
| MEDIUM | Merge Without Review | No     |

This change replaces the usage of [`java.io.File#createTempFile`](https://docs.oracle.com/en/java/javase/20/docs/api/java.base/java/io/File.html#createTempFile(java.lang.String,java.lang.String)) with [`java.nio.file.Files#createTempFile`](https://docs.oracle.com/en/java/javase/20/docs/api/java.base/java/nio/file/Files.html#createTempFile(java.lang.String,java.lang.String,java.nio.file.attribute.FileAttribute...)) which has more secure attributes.

The `java.io.File#createTempFile()` method creates a file that is world-readable and world-writeable, which is almost never necessary. Also, the file created is placed in a predictable directory (e.g., `/tmp`). Having predictable file names, locations, and will lead to many types of vulnerabilities. History has shown that this insecure pattern can lead to [information leakage](https://www.cvedetails.com/cve/CVE-2021-28168/), [privilege escalation](https://www.cvedetails.com/cve/CVE-2021-29428/) and even [code execution](https://www.openwall.com/lists/oss-security/2022/02/25/3).

Our changes look something like this:

```diff
+  import java.nio.file.Files;
   ...
-  File txtFile = File.createTempFile("acme", ".txt");
+  File txtFile = Files.createTempFile("acme", ".txt").toFile();
```


## References
 * [https://cwe.mitre.org/data/definitions/378.html](https://cwe.mitre.org/data/definitions/378.html)
 * [https://docs.fluidattacks.com/criteria/vulnerabilities/160/](https://docs.fluidattacks.com/criteria/vulnerabilities/160/)
 * [https://github.com/apache/druid/issues/11130](https://github.com/apache/druid/issues/11130)
 * [https://owasp.org/www-community/vulnerabilities/Insecure_Temporary_File](https://owasp.org/www-community/vulnerabilities/Insecure_Temporary_File)
 * [https://nvd.nist.gov/vuln/detail/CVE-2022-41954](https://nvd.nist.gov/vuln/detail/CVE-2022-41954)
 * [https://www.cvedetails.com/vulnerability-list/cwe-378/vulnerabilities.html](https://www.cvedetails.com/vulnerability-list/cwe-378/vulnerabilities.html)
