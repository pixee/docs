---
sidebar_position: 3
---

# Preferences

Pixeebot works immediately after installation without any further configuration. Yet, Pixeebot exposes preferences for users to tailor its behavior when desirable.

Users may set Pixeebot preferences at either the organization or repository levels.

1. **Repository preferences:**
   Create a `pixeebot.yaml` file in the `.github` directory of the target repository. Preferences in the target repository will take precedence over other preferences.

2. **Organization-wide preferences:**
   Alternatively, you can create the `pixeebot.yaml` file in the `.github` directory of your `.github` repository. This will serve as the global preferences that apply to all repositories in this installation.

## Codemod catalogs

Pixeebot offers three codemod catalogs to choose from in order to tune the type of improvements received.

- **Less**: Pixeebot will only suggest improvements for findings identified by a third-party security tool. See the [third-party security tools](/code-scanning-tools/overview) page for more information.
- **Moderate**: In addition to third-party security tool findings, Pixeebot will also suggest fixes for its own security findings.
- **More**: Includes everything from the Less and Moderate catalogs, along with additional suggestions Pixeebot identifies, such as style improvements and best practices.

### Selecting a catalog

During the onboarding process, users will be given the option to select a catalog preference for the organization they are installing on. This will determine the default catalog used for any repositories in that organization. If this step is skipped and no preference is selected, the Moderate catalog will be used by default. At any time, changes can be made by visiting the Pixee dashboard and selecting "View / change default preference" in the User menu.

Additionally, the catalog value can be configured on a per-repository/per-organization basis by updating the YAML configuration file. See the [Properties](#properties) section below for more information.

## Properties

### `ai`

Contains settings related to AI functionality.

#### `allow_llm_access`

`true` by default.

Setting to `false` disables Pixeebot features that [rely on generative AI](faqs.md) to analyze your code.

Example:

```yaml
ai:
  allow_llm_access: false
```

### `codemods`

Contains optional preferences related to the codemod catalog Pixeebot uses to
make changes to repositories.

#### `catalog`

A string value that determines the codemod catalog used for code improvements.
The value can be set to `less`, `moderate`, or `more`.

Example:

```yaml
codemods:
  catalog: more
```

#### `exclude`

A set of codemods to exclude from the catalog. Each codemod is identified by its
codemod ID.

Example:

```yaml
codemods:
  exclude:
    - pixee:python/https-connection
```

#### `prepend`

A list of non-default codemods to prepend to the codemod catalog. This list is
ordinal: the continuous improvement campaign will execute the codemods in the
order given.

Example:

```yaml
codemods:
  prepend:
    - pixee:python/use-walrus-if
```

### `paths`

Contains optional preferences for controlling the files and directories that are
included in Pixeebot analysis.

#### `exclude`

A set of paths to files or directories to exclude from Pixeebot analysis. Each
path is relative to the root of the repository. Each path in the set may be a
file, directory, or UNIX glob pattern.

Example:

```yaml
paths:
  exclude:
    - buildSrc/
```

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
    permissions:
      contents: write

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

## Configuring Lockfile Updates

Some Pixeebot fixes add dependencies to your project. For package managers that rely on lockfiles, it is important to update the lockfile after adding dependencies. We recommend using a GitHub Action to automatically update lockfiles for Pixeebot PRs.

### Python: Poetry

[Poetry](https://python-poetry.org/) is a popular Python package manager that uses a `pyproject.toml` file to manage dependencies. To automatically update the Poetry lockfile for Pixeebot PRs that add dependencies, add the following GitHub action workflow to your repository:

```yaml
name: Update Poetry Lockfile

on:
  pull_request:
    paths:
      - "pyproject.toml"

jobs:
  update-lock-file:
    if: github.event.pull_request.user.login == 'pixeebot[bot]'
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository
        uses: actions/checkout@v3
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.11" # Specify your Python version here

      - name: Install Poetry
        run: pip install poetry

      - name: Generate lock file
        run: poetry update

      - name: Commit and push changes
        uses: stefanzweifel/git-auto-commit-action@v5
        with:
          commit_message: ":lock: Update Poetry lock file"
```
