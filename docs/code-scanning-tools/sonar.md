---
title: "SonarCloud"
sidebar_position: 1
---

# SonarCloud

Pixee can automatically fix issues detected by [SonarCloud](https://www.sonarsource.com/products/sonarcloud/). This page explains how to integrate your SonarCloud results with Pixee.

:::info
Looking to fix [SonarQube](https://www.sonarsource.com/products/sonarqube/) issues? See [SonarQube](./sonarqube.md)
:::

## How to Get Started

1. Install [Pixee GitHub Application](https://github.com/marketplace/pixeebot-automated-code-fixes)
2. Install [Sonar GitHub Application](https://github.com/marketplace/sonarcloud)
3. Add [Upload Tool Results GitHub Action](https://github.com/marketplace/actions/upload-tool-results-to-pixeebot)
4. Start receiving Pull Requests from Pixee that address Sonar findings.

## More Information

Pixee fixes issues detected by SonarCloud when repositories have both the Pixee and SonarCloud GitHub Apps installed.

For public repositories using SonarCloud, Pixee retrieves results from sonarcloud.io automatically with no further configuration required from the user.

For private repositories using SonarCloud, use the [pixee/upload-tool-results-action](https://github.com/pixee/upload-tool-results-action) GitHub Action to synchronize SonarCloud findings with Pixee.

<iframe width="100%" height="315" src="https://www.youtube.com/embed/-Rx5NrZ8zDw?si=B3ktZrOH19fWNLTg" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>
