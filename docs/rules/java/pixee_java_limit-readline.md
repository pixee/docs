---
title: Limit Java readLine()
sidebar_position: 1
---

## pixee:java/limit-readline

| Importance | Review Guidance            | Requires SARIF Tool |
|------------|----------------------------|---------------------|
 | Medium     | Merge After Cursory Review | No                  |

This rule hardens all [`BufferedReader#readLine()`](https://docs.oracle.com/javase/8/docs/api/java/io/BufferedReader.html#readLine--) calls against attack.

There is no way to safely call `BufferedReader#readLine()` on a remote stream since it is, by its nature, a read that will only be terminated by the stream provider providing a newline character. A stream influenced by an attacker could keep providing bytes until the JVM runs out of memory, causing a crash.

Fixing it is straightforward using [a secure API](https://github.com/openpixee/java-security-toolkit/blob/main/src/main/java/io/pixee/security/BoundedLineReader.java) which limits the amount of expected characters to some sane amount. The changes from this rule look like this:

```diff
+import io.openpixee.security.BoundedLineReader;
...
BufferedReader reader = getReader();
-String line = reader.readLine(); // unlimited read, can lead to DoS
+String line = BoundedLineReader.readLine(reader, 5_000_000); // limited to 5MB
```


If you have feedback on this rule, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why does this rule require an OpenPixee dependency?

We always prefer to use existing controls built into Java, or a control from a well-known and trusted community dependency. However, we cannot find any such control. If you know of one, [please let us know](https://pixee.ai/feedback/).

### Why is this rule marked as Merge After Cursory Review?

This rule sets a maximum of 5MB allowed per line read by default. It is unlikely but possible that your code may receive lines that are greater than 5MB _and_ you'd still be interested in reading them, so there is some nominal risk of exceptional cases. If you want to customize the behavior of the rule to have a higher default for your repository, you can change its [Rule Settings](./pixee_java_limit-readline.md#rule-settings).

## Rule Settings

### Default Line Maximum
If you want to set a specific line maximum for your repository, add the following section to your `.github/pixeebot/rule-settings.yaml`:
```yaml
rules:
  name: pixee:java/limit-readline
  properties:
    maximumLineRead: 25000000
```
This change allows each line read to 25MB instead of the default 5MB.

## References
* [Security Control (BoundedLineReader.java) source code](https://github.com/openpixee/java-security-toolkit/blob/main/src/main/java/io/openpixee/security/BoundedLineReader.java)
* [https://cwe.mitre.org/data/definitions/400.html](https://cwe.mitre.org/data/definitions/400.html)
* [https://vulncat.fortify.com/en/detail?id=desc.dataflow.abap.denial_of_service](https://vulncat.fortify.com/en/detail?id=desc.dataflow.abap.denial_of_service)
