---
sidebar_position: 1
---

# Introducing Pixeebot 👋

Pixeebot is a [GitHub app](https://github.com/apps/pixeebot/) that automatically improves your code. It acts like a developer on your team by reviewing your code for you, and recommending changes to enhance code quality, performance, and security. Pixeebot opens merge-ready pull requests (PRs) for each recommendation, so all you have to do is review and merge. 

Pixeebot is powered by our open source toolkit [codemodder](https://codemodder.io/), a pluggable framework for building expressive codemods. These codemods help power Pixeebot’s recommendations, and are continuously updated to ensure Pixeebot’s recommendations align with industry standards and best practices.

### How does Pixeebot help me?

Pixeebot monitors your repositories and provides fixes in two different ways:

1. :on: **Continuous Improvement:** monitors your default branch and sends you pull requests with fixes.
2. :seedling: **PR Improvement:** checks each new pull request (PR) and recommends improvements.

### What types of recommendations does Pixeebot make? 

Pixeebot is built to find and fix a variety of problems, whether they are performance and quality issues or known security vulnerabilities. Here are a few of the most common issues Pixeebot resolves:

* NullPointerExceptions 
* Cross Site Scripting (XSS) and XML External Entity (XXE) attack vulnerabilities 
* Denial of Service (DoS) attack vulnerabilities 
* SQL injection vulnerailities
* Removal of unnecessary F-strings

### How can I test Pixeebot?

Pixeebot is quick to install and starts working immediately upon activation. While Pixeebot is designed for repositories of all sizes, it is most effective at identifying vulnerabilities in active medium to large-sized projects. If you need a repository to test with, we recommend trying Pixeebot out with a deliberately insecure application like OWASP’s WebGoat: [https://github.com/WebGoat/WebGoat](https://github.com/WebGoat/WebGoat) 

Working with an application like WebGoat can give you an idea of how Pixeebot works, before installing it directly on your personal or professional repositories. 

### What environment & languages does Pixeebot support?

Pixeebot is currently available for Java and Python repositories on GitHub, with support for additional languages coming soon. Have a language you’d like to see supported? Let us know in an email to [hi@pixee.ai](hi@pixee.ai). We’d love to hear from you! 

### What does Pixeebot cost?

Pixeebot is currently free for all users. We will add paid tiers in the future.
