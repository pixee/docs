---
title: "Sonar"
sidebar_position: 1
---

# Sonar

Pixeebot can automatically fix issues detected by [Sonar](https://www.sonarsource.com/products/sonarcloud/). This page explains how to integrate your Sonar results with Pixeebot.

## How to Get Started

1. Install [pixeebot Github Application](https://github.com/marketplace/pixeebot-automated-code-fixes)
2. Install [Sonar Github Application](https://github.com/marketplace/sonarcloud)
3. Add [Upload Tool Results Github Action](https://github.com/marketplace/actions/upload-tool-results-to-pixeebot)
4. Start receiving Pull Requests that address Sonar findings.


## More information

Pixeebot fixes issues detected by Sonar when repositories have both the Pixeebot and Sonar GitHub Apps installed.

For public repositories using SonarCloud, Pixeebot retrieves results from sonarcloud.io automatically with no further configuration required from the user.

For private repositories using SonarCloud, use the [pixee/upload-tool-results-action](https://github.com/pixee/upload-tool-results-action) GitHub Action to synchronize SonarCloud findings with Pixeebot.


<iframe width="100%" height="315" src="https://www.youtube.com/embed/-Rx5NrZ8zDw?si=B3ktZrOH19fWNLTg" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>
