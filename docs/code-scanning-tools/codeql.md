---
title: "CodeQL"
sidebar_position: 3
---
# CodeQL

Pixeebot can automatically fix issues detected by [CodeQL](https://codeql.github.com/).  

No setup is required.  The codemods listed below support the matching [prebuilt queries](https://docs.github.com/en/code-security/code-scanning/managing-your-code-scanning-configuration/java-kotlin-built-in-queries) for Java analysis

## Codemods
* [Database Resource Leak](https://docs.pixee.ai/codemods/java/codeql_java_database-resource-leak/)
* [Input Resource Leak](https://docs.pixee.ai/codemods/java/codeql_java_input-resource-leak/)
* [Insecure Cookie](https://docs.pixee.ai/codemods/java/codeql_java_insecure-cookie/)
* [Expression Language Injection](https://docs.pixee.ai/codemods/java/codeql_java_jexl-expression-injection/)
* [Maven Non-HTTPS URL](https://docs.pixee.ai/codemods/java/codeql_java_maven_non-https-url/)
* [Missing JWT Signature Check](https://docs.pixee.ai/codemods/java/codeql_java_missing-jwt-signature-check/)
* [Output Resource Leak](https://docs.pixee.ai/codemods/java/codeql_java_output-resource-leak/)
* [Stack Trace Exposure](https://docs.pixee.ai/codemods/java/codeql_java_stack-trace-exposure/)







