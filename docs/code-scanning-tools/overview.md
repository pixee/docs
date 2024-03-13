---
sidebar_position: 4
---

# Code Scanning Tool Fixes

Pixeebot automatically fixes issues detected by code scanning tools when synced with the results of those scans. This page explains how to integrate code scanning tools with Pixeebot, so that Pixeebot may fix the issues those tools find.

## Sonar

Pixeebot fixes issues detected by Sonar when repositories have both the Pixeebot and Sonar GitHub Apps installed.

For public repositories using SonarCloud, Pixeebot retrieves results from sonarcloud.io automatically with no further configuration required from the user.

For private repositories using SonarCloud, use the [pixee/upload-tool-results-action](https://github.com/pixee/upload-tool-results-action) GitHub Action to synchronize SonarCloud findings with Pixeebot.

## CodeQL

Coming soon!
