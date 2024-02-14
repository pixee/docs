---
title: "Fixed overly permissive file permissions (issue discovered by Semgrep)"
sidebar_position: 1
---

## semgrep:java/java.lang.security.audit.overly-permissive-file-permission.overly-permissive-file-permission 

| Importance  | Review Guidance      | Requires Scanning Tool |
|-------------|----------------------|------------------------|
| MEDIUM | Merge After Cursory Review | Yes (Semgrep)     |

This change removes excessive privilege from a file that appears to be overly permissive. Files can be granted privileges to the file's owner, the file owner's group, or "others" -- meaning anyone else. It is hard to imagine the need for a file to be readable, writable or executable by anyone other than the file's owner or the file owner's group in modern software development. 

If a file is readable by "others", it could be read by a malicious system user to retrieve sensitive information or useful implementation details. If the file is writable by "others", the application could be tricked into performing actions on data provide by malicious users. Allowing execution of a file by "others" could allow malicious users to run arbitrary code on the server. 

Our changes look something like this:

```diff
  Set<PosixFilePermission> startupPermissions = new HashSet<PosixFilePermission>();
- startupPermissions.add(PosixFilePermission.OTHERS_WRITE);
+ startupPermissions.add(PosixFilePermission.GROUP_WRITE);
  Files.setPosixFilePermissions(startupScript, startupPermissions);
  
- Set<PosixFilePermission> shutdownPermissions = PosixFilePermissions.fromString("rwxrwxrwx");
+ Set<PosixFilePermission> shutdownPermissions = PosixFilePermissions.fromString("rwxrwx---");
  Files.setPosixFilePermissions(shutdownScript, shutdownPermissions);
```

Note: It's worth considering whether you could use a more restrictive permission than `GROUP_WRITE` here. For example, if the file is owned by the same user that's running the application, you could use `OWNER_WRITE` instead.


## References
 * [https://find-sec-bugs.github.io/bugs.htm#OVERLY_PERMISSIVE_FILE_PERMISSION](https://find-sec-bugs.github.io/bugs.htm#OVERLY_PERMISSIVE_FILE_PERMISSION)
 * [https://registry.semgrep.dev/rule/java.lang.security.audit.overly-permissive-file-permission.overly-permissive-file-permission](https://registry.semgrep.dev/rule/java.lang.security.audit.overly-permissive-file-permission.overly-permissive-file-permission)
 * [https://cwe.mitre.org/data/definitions/732.html](https://cwe.mitre.org/data/definitions/732.html)
