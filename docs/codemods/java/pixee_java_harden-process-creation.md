---
title: Harden Process Creation
sidebar_position: 1
---


## pixee:java/harden-process-creation
| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
 | High       | Merge Without Review | No                  |

This codemod hardens all instances of [Runtime#exec()](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/Runtime.html) to offer protection against attack.

Left unchecked, `Runtime#exec()` can execute any arbitrary system command. If an attacker can control part of the strings used to as program paths or arguments, they could execute arbitrary programs, install malware, and anything else they could do if they had a shell open on the application host.

Our change introduces a sandbox which protects the application:

```diff
+ import io.github.pixee.security.SystemCommand;
  ...
- Process p = Runtime.getRuntime().exec(command);
+ Process p = SystemCommand.runCommand(Runtime.getRuntime(), command);
```

The default restrictions applied are the following:
* **Prevent command chaining**. Many exploits work by injecting command separators and causing the shell to interpret a second, malicious command. The `SystemCommand#runCommand()` attempts to parse the given command, and throw a `SecurityException` if multiple commands are present.
* **Prevent arguments targeting sensitive files.** There is little reason for custom code to target sensitive system files like `/etc/passwd`, so the sandbox prevents arguments that point to these files that may be targets for exfiltration.

There are [more options for sandboxing](https://github.com/pixee/java-security-toolkit/blob/main/src/main/java/io/github/pixee/security/SystemCommand.java#L15) if you are interested in locking down system commands even more.

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this codemod marked as Merge Without Review?

We believe this change is safe and effective. The behavior of hardened `Runtime#exec()` calls will only throw `SecurityException` if they see behavior involved in malicious code execution, which is extremely unlikely to in normal operation.

## Codemod Settings

N/A

## References
* [Security Control (SystemCommand.java) source code](https://github.com/pixee/java-security-toolkit/blob/main/src/main/java/io/github/pixee/security/SystemCommand.java)
* [https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
* [https://wiki.sei.cmu.edu/confluence/display/java/IDS07-J.+Sanitize+untrusted+data+passed+to+the+Runtime.exec%28%29+method](https://wiki.sei.cmu.edu/confluence/display/java/IDS07-J.+Sanitize+untrusted+data+passed+to+the+Runtime.exec%28%29+method)