---
title: 'Introduced protections against "zip slip" attacks'
sidebar_position: 1
---

## pixee:java/harden-zip-entry-paths

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| HIGH       | Merge Without Review | No                     |

This change updates all new instances of [ZipInputStream](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/zip/ZipInputStream.html) to protect against malicious entries that attempt to escape their "file root" and overwrite other files on the running filesystem.

Normally, when you're using `ZipInputStream` it's because you're processing zip files. That code might look like this:

```java
File file = new File(unzipTargetDirectory, zipEntry.getName()); // use file name from zip entry
InputStream is = zip.getInputStream(zipEntry); // get the contents of the zip entry
IOUtils.copy(is, new FileOutputStream(file)); // write the contents to the provided file name
```

This looks fine when it encounters a normal zip entry within a zip file, looking something like this pseudo-data:

```binary
path: data/names.txt
contents: Zeus\nHelen\nLeda...
```

However, there's nothing to prevent an attacker from sending an evil entry in the zip that looks more like this:

```binary
path: ../../../../../etc/passwd
contents: root::0:0:root:/:/bin/sh
```

Yes, in the above code, which looks like [every](https://stackoverflow.com/a/23870468) [piece](https://stackoverflow.com/a/51285801) of [zip-processing](https://kodejava.org/how-do-i-decompress-a-zip-file-using-zipinputstream/) code you can [find](https://www.tabnine.com/code/java/classes/java.util.zip.ZipInputStream) on the [Internet](https://www.baeldung.com/java-compress-and-uncompress), attackers could overwrite any files to which the application has access. This rule replaces the standard `ZipInputStream` with a hardened subclass which prevents access to entry paths that attempt to traverse directories above the current directory (which no normal zip file should ever do.) Our changes end up looking something like this:

```diff
+ import io.github.pixee.security.ZipSecurity;
  ...
- var zip = new ZipInputStream(is, StandardCharsets.UTF_8);
+ var zip = ZipSecurity.createHardenedInputStream(is, StandardCharsets.UTF_8);
```

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

We believe this change is safe and effective. The behavior of hardened `ZipInputStream` instances will only be different if malicious zip entries are encountered.

## References

- [https://snyk.io/research/zip-slip-vulnerability](https://snyk.io/research/zip-slip-vulnerability)
- [https://github.com/snyk/zip-slip-vulnerability](https://github.com/snyk/zip-slip-vulnerability)
- [https://wiki.sei.cmu.edu/confluence/display/java/IDS04-J.+Safely+extract+files+from+ZipInputStream](https://wiki.sei.cmu.edu/confluence/display/java/IDS04-J.+Safely+extract+files+from+ZipInputStream)
- [https://vulncat.fortify.com/en/detail?id=desc.dataflow.java.path_manipulation_zip_entry_overwrite](https://vulncat.fortify.com/en/detail?id=desc.dataflow.java.path_manipulation_zip_entry_overwrite)
