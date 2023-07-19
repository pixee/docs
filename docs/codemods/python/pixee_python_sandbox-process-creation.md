---
title: Sandbox Process Creation
sidebar_position: 1
draft: true
---


## pixee:python/sandbox-process-creation
| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
 | High       | Merge Without Review | No                  |

This codemod sandboxes all instances of [subprocess.run](https://docs.python.org/3/library/subprocess.html#subprocess.run) and [subprocess.call](https://docs.python.org/3/library/subprocess.html#subprocess.call) to offer protection against attack.

Left unchecked, `subprocess.run` and `subprocess.call` can execute any arbitrary system command. If an attacker can control part of the strings used as program paths or arguments, they could execute arbitrary programs, install malware, and anything else they could do if they had a shell open on the application host.

Our change introduces a sandbox which protects the application:

```diff
import subprocess
+ from security import safe_command
...
- subprocess.run("echo 'hi'", shell=True)
+ safe_command.run(subprocess.run, "echo 'hi'", shell=True)

- subprocess.call(["ls", "-l"])
+ safe_command.call(subprocess.call, ["ls", "-l"])
```

The default `safe_command` restrictions applied are the following:
* **Prevent command chaining**. Many exploits work by injecting command separators and causing the shell to interpret a second, malicious command. The `safe_command` functions attempt to parse the given command, and throw a `SecurityException` if multiple commands are present.
* **Prevent arguments targeting sensitive files.** There is little reason for custom code to target sensitive system files like `/etc/passwd`, so the sandbox prevents arguments that point to these files that may be targets for exfiltration.

There are [more options for sandboxing](https://github.com/pixee/python-security/blob/main/src/security/safe_command/api.py#L5) if you are interested in locking down system commands even more.

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this codemod marked as Merge Without Review?

We believe this change is safe and effective. The behavior of sandboxing `subprocess.run` and `subprocess.call` calls will only throw `SecurityException` if they see behavior involved in malicious code execution, which is extremely unlikely to happen in normal operation.

## Codemod Settings

N/A

## References
* [Safe command API source code](https://github.com/pixee/python-security/blob/main/src/security/safe_command/api.py)
* [https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)