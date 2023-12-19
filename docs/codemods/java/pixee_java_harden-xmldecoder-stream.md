---
title: Harden XMLDecoder Usage
sidebar_position: 1
---


## pixee:java/harden-xmldecoder-stream
| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
 | High       | Merge Without Review | No                     |

This codemod hardens usage of Java's [`java.beans.XMLDecoder`](https://docs.oracle.com/en/java/javase/17/docs/api/java.desktop/java/beans/XMLDecoder.html) APIs to prevent remote code execution attacks.

The `XMLDecoder` type is meant to serialize Java beans to and from XML. It has a lot of power built into it, so it is not meant for use with untrusted data. If attackers can influence the XML being deserialized, they can execute arbitrary system commands with exploits [like this](https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/web/java-XMLDecoder-RCE.md) one, which causes the host to open a remote shell on port 4444:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_102" class="java.beans.XMLDecoder">
    <void class="java.lang.ProcessBuilder">
        <array class="java.lang.String" length="6">
            <void index="0">
                <string>/usr/bin/nc</string>
            </void>
            <void index="1">
                <string>-l</string>
            </void>
            <void index="2">
                <string>-p</string>
            </void>
            <void index="3">
                <string>4444</string>
            </void>
            <void index="4">
                <string>-e</string>
            </void>
            <void index="5">
                <string>/bin/bash</string>
            </void>
        </array>
        <void method="start" id="process">
        </void>
    </void>
</java>
```

Our change wraps all `InputStream` objects passed to `XMLDecoder` constructors with a wrapper stream that attempts to detect the deserialization of dangerous types (e..g, `java.lang.Runtime` for executing system commands, `java.io.FileOutputStream` for overwriting files, etc.). This is not a complete protection, because attackers could possibly build gadget chains that avoid direct invocation of these particular types to accomplish their goals, but it does significantly raise the bar for exploitation. Here's what a typical change looks like:

```diff
+ import io.github.pixee.security.XMLDecoderSecurity;
  ...
- XMLDecoder decoder = new XMLDecoder(is);
+ XMLDecoder decoder = new XMLDecoder(XMLDecoderSecurity.hardenStream(is), null, null);
  AcmeOrder order = (AcmeOrder)decoder.readObject();
  return order;
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why is this codemod marked as Merge Without Review?

We believe this change is safe and effective. The behavior of hardened `XMLDecoder` instances will only throw `SecurityException` if they see types being deserialized are involved in code execution, which is extremely unlikely to in normal operation.

## Codemod Settings

N/A

## References
* [Security Control (XMLDecoderSecurity.java) source code](https://github.com/pixee/java-security-toolkit/blob/main/src/main/java/io/github/pixee/security/XMLDecoderSecurity.java)
* [https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/web/java-XMLDecoder-RCE.md](https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/web/java-XMLDecoder-RCE.md)
* [http://diniscruz.blogspot.com/2013/08/using-xmldecoder-to-execute-server-side.html](http://diniscruz.blogspot.com/2013/08/using-xmldecoder-to-execute-server-side.html)
* [https://github.com/pwntester/XMLDecoder](https://github.com/pwntester/XMLDecoder)
