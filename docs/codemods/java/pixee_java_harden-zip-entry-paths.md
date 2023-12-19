---
title: Harden Against "Zip Slip"
sidebar_position: 1
---


## pixee:java/harden-zip-entry-paths
| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
 | High       | Merge Without Review | No                     |

This codemod hardens instances of [ZipInputStream](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/zip/ZipInputStream.html) to protect against malicious entries that attempt to escape their "file root" and overwrite other files on the running filesystem.

Normally, when you're using `ZipInputStream`, it's because you're processing zip files. That code might look like this:

```java
File file = new File(unzipTargetDirectory, zipEntry.getName()); // use file name from zip entry
InputStream is = zip.getInputStream(zipEntry); // get the contents of the zip entry
IOUtils.copy(is, new FileOutputStream(file)); // write the contents to the provided file name
```

This looks fine when it encounters a normal zip entry within a zip file, which could look something like this pseudo-data:
```binary
path: data/names.txt
contents: Zeus\nHelen\nLeda...
```

However, there's nothing to prevent an attacker from sending an evil entry in the zip that looks more like this:
```binary
path: ../../../../../etc/passwd
contents: root::0:0:root:/:/bin/sh
```

In the above code, which looks like [most](https://stackoverflow.com/a/23870468) [pieces](https://stackoverflow.com/a/51285801) of [zip-processing](https://kodejava.org/how-do-i-decompress-a-zip-file-using-zipinputstream/)  code you can [find](https://www.tabnine.com/code/java/classes/java.util.zip.ZipInputStream) on the [Internet](https://www.baeldung.com/java-compress-and-uncompress), attackers could overwrite any files to which the application has access. Our change replaces the standard `ZipInputStream` with a hardened subclass which prevents access to entry paths that attempt to traverse directories above the current directory (which no normal zip file should ever do.) They look something like this:

```diff
+ import io.github.pixee.security.ZipSecurity;
- var zip = new ZipInputStream(is, StandardCharsets.UTF_8);
+ var zip = ZipSecurity.createHardenedInputStream(is, StandardCharsets.UTF_8);
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this codemod marked as Merge Without Review?

We believe this change is safe and effective. The behavior of hardened `XStream` instances will only be different if the types being deserialized are involved in code execution, which is extremely unlikely to in normal operation.   

## Codemod Settings

N/A

## References
* [Security Control (XMLInputFactorySecurity.java) source code](https://github.com/pixee/java-security-toolkit/blob/main/src/main/java/io/github/pixee/security/XMLInputFactorySecurity.java)
* [https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
* [https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md)