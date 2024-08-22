---
sidebar_position: 1
---

# Introducing Pixee 👋

Pixee is your automated product security engineer.

Pixee triages and fixes issues detected by your [code scanning tools](/code-scanning-tools/overview). To make the fix, we'll send you a pull request.

Pixee is powered by the open-source [codemodder framework](https://codemodder.io/). These codemods power Pixee's fixes, and are continuously updated to ensure Pixee's recommendations align with industry standards and best practices.

### How does Pixee help me?

1. 🗃️ **Continuous Improvement:** works down your backlog of issues and keeps your codebase secure.
2. :seedling: **PR Improvement:** checks each new pull request (PR) and recommends improvements.
3. 🔎 **Triage**: identifies false positives and prioritizes issues that need fixing.

### What types of issues can Pixee triage and fix?

Pixee can triage and fix a wide range of security issues detected by code scanning tools. Many of these issues are common across tools and languages, such as:

- SQL Injection
- Cross-Site Scripting (XSS)
- Insecure Deserialization
- Insecure Randomness
- XML External Entities (XXE)
- Insecure Cookie Handling
- Command Injection
- Insecure Configuration
- ... and many more!

### How can I test Pixee?

Pixee is most easily tried as a GitHub App on the [GitHub Marketplace](https://github.com/apps/pixeebot/). We provide a free tier on our cloud offering that can be installed on any public or private repository. After adding Pixee, you need to get some code scanning results to show a breadth of fixes available. To do that, try adding [SonarCloud](https://www.sonarsource.com/products/sonarcloud/) to it. This is a great way to get started with Pixee and see how it can help to harden and secure your code, and triage your code scanner alerts.

If you need a repository to test with, we recommend trying Pixee out with a deliberately insecure application. Template repositories containing Java and Python test applications are available in PixeeSandbox: [https://github.com/PixeeSandbox](https://github.com/PixeeSandbox).

Testing with these deliberately insecure applications can give you an idea of how Pixee works, before installing it directly on your personal or professional repositories.

For additional details, see the [Installation](/installing) page.

Pixee also supports on-premises deployment for organizations that require additional security or compliance measures. To learn more about Pixee on-premises solutions, please [contact us](https://pixee.ai/demo-landing-page).

### What environment & languages does Pixee support?

Pixee supports a wide variety of languages and code scanning tools. For a full list of supported languages, tools, and rules, see the [Code Scanning Tools](/code-scanning-tools/overview) page.

### What does Pixee cost?

Please see https://www.pixee.ai/pricing.
