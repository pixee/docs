---
title: Harden Java serialization calls
sidebar_position: 1
---

## pixee:java/harden-java-deserialization 

| Importance | Review Guidance      | Requires SARIF Tool |
|------------|----------------------|---------------------|
 | High       | Merge Without Review | No                  |

This rule hardens Java deserialization operations against attack. Even a simple operation like an object deserialization is unfortunately a real opportunity to yield control of your system to an attacker. In fact, without specific protections, any object deserialization call can lead to arbitrary code execution. The JavaDoc [now even says](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/io/ObjectInputFilter.html):

> Deserialization of untrusted data is inherently dangerous and should be avoided.

Let's discuss the attack. In Java, types can customize how they should be deserialized by specifying a `readObject()` method like this real world example from an [old version of Spring](https://github.com/spring-projects/spring-framework/blob/4.0.x/spring-core/src/main/java/org/springframework/core/SerializableTypeWrapper.java#L404):

```java
static class MethodInvokeTypeProvider implements TypeProvider {
    private final TypeProvider provider;
    private final String methodName;

    private void readObject(ObjectInputStream inputStream) {
        inputStream.defaultReadObject();
        Method method = ReflectionUtils.findMethod(
            this.provider.getType().getClass(),
            this.methodName
        );
        this.result = ReflectionUtils.invokeMethod(method,this.provider.getType());
    }
}
```

Analyzing this code reveals a terrifying conclusion. If an attacker presents this object to be deserialized by your app, your app will take a class and a method name from the attacker, and then call them. Note that an attacker can provide any serliazed type -- it doesn't have to be the one you're expecting, and it will still deserialize.

Attackers can repurpose the logic of selected types within the Java classpath (called "gadgets") and chain them together to achieve arbitrary remote code execution. There are a limited number of publicly known gadgets that can be used for attack, and our change simply inserts an [ObjectInputFilter](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/io/ObjectInputStream.html#setObjectInputFilter(java.io.ObjectInputFilter)) into the `ObjectInputStream` to prevent them from being used.

```diff
+import io.openpixee.security.ObjectInputFilters;

...

ObjectInputStream ois = new ObjectInputStream(is);
+ObjectInputFilters.enableObjectFilterIfUnprotected(ois);
AcmeObject acme = (AcmeObject)ois.readObject();
```

This is a tough vulnerability class to understand, but it is deadly serious because it's the highest impact possible (remote code execution) and extremely likely (automated tooling can exploit.) It's best to remove deserialization, but our protections will protect you from all known exploitation strategies.

If you have feedback on this rule, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q. 

### Why does this rule require an OpenPixee dependency?

We always prefer to use existing controls built into Java, or a control from a well-known and trusted community dependency. However, we cannot find any such control. If you know of one, [please let us know](https://pixee.ai/feedback/).

### Why is this rule marked as Merge Without Review?

The protection works by denying deserialization of "gadget types", which are not types that applications typically deserialize, such as:
* `org.apache.commons.collections.functors.InvokerTransformer`
* `mozilla.javascript.ScriptableObject$Slot`
* `com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase`

A common thread about these types is that they are either internal types or inner types, and thus not intended for application use. There are more public gadgets, but they are not expected to be deserialized either, and represent attacks (e.g., `java.lang.ProcessBuilder`).   

Given all of this, the risk to an application to merge this protection are effectively zero.

## Rule Settings

N/A

## References
* [Security Control (ObjectInputFilters.java) source code](https://github.com/openpixee/java-security-toolkit/blob/main/src/main/java/io/openpixee/security/ObjectInputFilters.java)
* [https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
* [https://portswigger.net/web-security/deserialization/exploiting](https://portswigger.net/web-security/deserialization/exploiting)
