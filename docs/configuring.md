---
sidebar_position: 3
---

# Configuring

There are two approaches to configuring Pixeebot:

1. **Target repository configuration:**
   Create a `pixeebot.yaml` file in the `.github` directory of the target repository. Configurations in the target repository will take precedence over other configurations.

2. **Global repository configuration:**
   Alternatively, you can create the `pixeebot.yaml` file in the `.github` directory of your `.github` repository. This will serve as a global configuration that applies to multiple repositories.

## YAML

A typical `.yaml` configuration file might look like this:

```yaml
ai:
  allow_llm_access: true
```

## Properties

### `ai`

Contains settings related to AI functionality.

#### `allow_llm_access`

Setting to `true` will enable Pixeebot to [send data to an LLM](faqs.md) while analyzing your code.

> **Note** This is the default configuration upon installation.

## Configuring automatic assignment

To automatically assign **reviewers** to Pixeebot PRs, consider [setting up a `CODEOWNERS` file](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners).

To automatically assign **users** to Pixeebot PRs, consider creating a GitHub action. Below is an example action that will assign all Pixeebot PRs to the user Octocat:

```yaml
on:
  pull_request:
    types: [opened, reopened, ready_for_review]

jobs:
  auto-assign:
    runs-on: ubuntu-latest
    if: github.actor == 'pixeebot[bot]'
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Assign PR to Collaborators
        uses: actions/github-script@v7
        with:
          script: |
            const collaborators = ['octocat']; // Replace with actual GitHub usernames
            github.rest.issues.addAssignees({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              assignees: collaborators
            })
```

Please contact us at help@pixee.ai with any questions, or if you would like more options for automatic assignment.

## Configuring Automatic Formatting

Many projects enforce a consistent code style by using automatic code formatters. This section contains instructions for configuring GitHub Actions to automatically format PRs that are created by Pixeebot.

### Python

The most popular Python code formatter is [Black](https://black.readthedocs.io/en/stable/). To automatically format PRs created by Pixeebot using Black, add the following GitHub action workflow to your repository:

```yaml
name: Format Pixeebot PRs

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  apply-black:
    if: github.event.pull_request.user.login == 'pixeebot[bot]'
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install black
        run: pip install black

      - name: Apply black formatting
        run: black .

      - name: Commit and push changes
        uses: stefanzweifel/git-auto-commit-action@v5
        with:
          commit_message: ":art: Apply formatting"
```

This action can be added to your repository by creating a `.github/workflows/pixeebot-autoformat-black.yml` file with the above content.

Note that it may be necessary to pin the version of Black to ensure that the formatting is consistent with your project's style. Depending on your project's configuration it may also be necessary to pass additional arguments to the `black` command to ensure that the correct settings are used.

### Java

For Java projects it is common to use a tool such as [Spotless](https://github.com/diffplug/spotless) to enforce code formatting. To automatically format PRs created by Pixeebot using Gradle to apply Spotless, add the following GitHub action workflow to your repository:

```yaml
name: Format Pixeebot PRs

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  spotless-apply:
    if: github.event.pull_request.user.login == 'pixeebot[bot]'
    runs-on: ubuntu-latest
    permissions:
      contents: write

    steps:
      - uses: actions/checkout@v4

      - name: "Setup JDK"
        uses: actions/setup-java@v4
        with:
          distribution: "temurin"
          java-version: "17"

      - name: 🐘Setup Gradle
        uses: gradle/actions/setup-gradle@v3

      - name: 🎨 Run spotless via Gradle
        run: ./gradlew spotlessApply

      - name: Commit and push changes
        uses: stefanzweifel/git-auto-commit-action@v5
        with:
          commit_message: ":art: Apply formatting"
```
