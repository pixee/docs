---
title: "SonarQube"
sidebar_position: 2
---

# SonarQube

Pixee can automatically fix issues detected by [SonarQube](https://www.sonarsource.com/products/sonarqube/).

For a given Sonar rule, Pixee's fixes are the same, regardless of whether the issue was detected by either SonarCloud or SonarQube. However, the steps required to integrate Pixee with these systems is different.

## How to Get Started

1. Install [Pixee GitHub Application](https://github.com/marketplace/pixeebot-automated-code-fixes)
2. Add [Upload Tool Results GitHub Action](https://github.com/marketplace/actions/upload-tool-results-to-pixeebot) to workflows that run SonarQube analysis.
3. Start receiving Pull Requests from Pixee that address Sonar findings.

## More Information

Pixee offers an on premises solution that can be deployed alongside your SonarQube instance. Please contact us at help@pixee.ai for detailed setup instructions.

SonarQube Community Edition lacks the features necessary to integrate with Pixee's PR experience.

<iframe width="100%" height="315" src="https://www.youtube.com/embed/-Rx5NrZ8zDw?si=B3ktZrOH19fWNLTg" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>
