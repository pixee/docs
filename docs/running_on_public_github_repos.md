---
sidebar_position: 2
---

# For public repositories without tools

This page describes how to help set up Pixee on a public GitHub repository that doesn't have any tools configured yet. Note that some features are only available in our enterprise offering.

## Step 1: Choose and set up your repository

On the repository you want to secure, enable GitHub _Issues_ so you can see the Pixee dashboard. You can always disable this later if, after you review, you prefer using our dashboard.

1. In your repository, go to `Settings` > `General`.
2. Under the `Features`, select `Issues`.

## Step 2: Choose CodeQL or SonarQube Cloud

For ease of integration, we suggest picking either CodeQL (through GitHub Advanced Security) or SonarQube Cloud. Both can be used to find vulnerabilities in your code, are free for public repositories, and offer simple onboarding. CodeQL is more focused on security than quality, but Sonar has a large rule based and is trusted by developers all over the world. Both are great choices.

### SonarQube Cloud

[Follow these instructions](https://docs.sonarsource.com/sonarqube-cloud/getting-started/github/) for installing SonarQube Cloud (to make things easier, login with your GitHub identity).

### CodeQL through GitHub Advanced Security (GHAS)

1. In your repository, go to `Settings` > `Code Security`.
2. Under the `Tools` > `CodeQL analysis`, hit `Set up`, then `Default`.

You may want to wait until the first scan finishes before moving onto the next step. You can see when it finishes by going to `Actions` and watching the progress of the recently-run CodeQL job.

## Step 3: Install Pixeebot

With the tool properly configured, the next step is to install Pixee.

1. Go to our [GitHub App page](https://github.com/apps/pixeebot/).
2. Click `Install` (or `Configure`) and follow the prompts from GitHub. You'll be directed to your Pixee dashboard once the installation process is complete.

## Step 4: See fixes available

1. Wait a few minutes for Pixee to process the results associated with the default branch.
2. There should be a new issue that shows which fixes are currently available.

import IssueDashboard from '/img/issue-dashboard.png';

<img src={IssueDashboard} alt="Issue dashboard" style={{width: 400}} />

You can use this dashboard to see what fixes are available, coming soon or summon Pixee to issue the fixes.

> Note: This GitHub-led experience will only show output from our AutoTriage AI agent when you make PRs that have security issues. To take advantage of this feature at scale, [contact us](https://pixee.ai/demo-landing-page)!
