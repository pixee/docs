---
sidebar_position: 5
---

# Core Codemods

Pixee uses the open-source [codemodder framework](https://codemodder.io/) to provide automated code improvements. These codemods are continuously updated to ensure Pixee's recommendations align with industry standards and best practices.

Pixeebot ships with a set of "core" codemods for [Java](https://github.com/pixee/codemodder-java) and [Python](https://github.com/pixee/codemodder-python) that do not require code scanning tool integration. These core codemods can be applied to your codebase to harden and improve your code in the form of pull requests.

You will get the most value out of Pixee by connecting it to your existing [code scanning tools and services](/code-scanning-tools/overview). This will allow Pixee to provide more accurate and relevant fixes for your codebase and to triage findings from those tools. Tool remediation codemods support a wider set of languages.
