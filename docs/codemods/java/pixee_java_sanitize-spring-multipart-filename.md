---
title: Sanitize Spring Multipart Filename
sidebar_position: 1
---

## pixee:java/sanitize-spring-multipart-filename 

| Importance | Review Guidance            | Requires SARIF Tool |
|------------|----------------------------|---------------------|
 | High       | Merge After Cursory Review | No                  |

This codemod hardens usage of the [Spring Web](https://github.com/spring-projects/spring-framework) multipart request and file uploading feature to prevent file overwrite attacks.

Although end users uploading a file through the browser can't fully control the file name, attackers armed with HTTP proxies, scripts or `curl` could manipulate the file to contain directory escape sequences and send in values like `../../../../../etc/passwd`. This is a common place that developers forget to distrust user input and end up including the attacker's file name in the path they end up writing.

Our change sanitizes the output of `FileItem#getName()`, stripping the value of null bytes and directory escape sequences, leaving a simple file name in the expected form. The code change is very simple and looks like this:

```diff
+import io.github.pixee.security.Filenames;
...
MultipartFile uploadedFile = parseFile(request);
-String name = uploadedFile.getOriginalFilename(); // vulnerable
+String name = Filenames.toSimpleFileName(uploadedFile.getOriginalFilename()); // safe
writeFile(new File("my_upload_dir", name));
```

## Codemod Settings

N/A

## References
* [Security Control (Filenames.java) source code](https://github.com/pixee/java-security-toolkit/blob/main/src/main/java/io/github/pixee/security/Filenames.java)
* [https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
* [https://portswigger.net/web-security/file-upload](https://portswigger.net/web-security/file-upload)