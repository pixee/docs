---
title: "Sanitized user-provided file names in HTTP multipart uploads"
sidebar_position: 1
---

## pixee:java/sanitize-apache-multipart-filename

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| HIGH       | Merge Without Review | No                     |

This change hardens usage of Apache Common's popular multipart request and [file uploading library](https://commons.apache.org/proper/commons-fileupload/) to prevent file overwrite attacks.

Although end users uploading a file through the browser can't fully control the file name, attackers armed with HTTP proxies, scripts or `curl` could manipulate the file to contain directory escape sequences and send in values like `../../../../../etc/passwd`. This is a common place that developers forget to distrust user input and end up including the attacker's file name in the path they end up writing.

Our change sanitizes the output of `FileItem#getName()`, stripping the value of null bytes and directory escape sequences, leaving a simple file name in the expected form. The code change is very simple and looks like this:

```diff
+ import io.github.pixee.security.Filenames;
  ServletFileUpload upload = new ServletFileUpload(factory);
  List<FileItem> items = upload.parseRequest(request);
  for (FileItem item : items) {
-   String name = item.getName();
+   String name = Filenames.toSimpleFileName(item.getName());
    writeFile(new File("my_upload_dir", name));
}
```

## References

- [https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [https://portswigger.net/web-security/file-upload](https://portswigger.net/web-security/file-upload)
