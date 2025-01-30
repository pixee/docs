---
sidebar_position: 8
---

# FAQs

### What are Pixee's AI features?

We utilize Large Language Models (LLMs) in some context-aware code fixes and to add code-specific comments, helping developers understand why a change is being recommended. Our triage features use LLMs to gather facts about the vulnerable code flow, wider technical context, in combination with deterministic analysis, to feed an expert recommendation system that produces our results.

### What is Pixee's AI policy?

At Pixee, we take your data privacy and security seriously. We want you to have peace of mind, knowing that your data will never be used to train AI models.

### How does Pixee handle my data?

Pixee is a platform focused on helping developers deliver higher quality code and places the utmost importance on our own security, including secure software development practices, IT practices, corporate controls and partner assessments. In case anyone asks, yes -- all data is encrypted in transit and at rest, and guaranteed to be destroyed.

As an aside, many of us have been in security our whole careers, and we're quite passionate about it! We document all of this and more in our [Security and Trust Center](https://trust.pixee.ai/).

### How will my information (i.e. code, projects, etc.) be used?

Each party agrees to hold data and confidential information of the other party in confidence and not to disclose, retain, or distribute such information to third parties or to use such information for any purpose whatsoever. Please take a look at our full [Privacy Policy](https://www.pixee.ai/privacy) for more detail.

### How do I know Pixee made changes?

Pixee works directly with your repositories through pull/merge requests, so you decide when and if you want to accept changes suggested by Pixee. You can find suggestions made by Pixee in the [Pixee Dashboard](https://app.pixee.ai/) as well as your repository's GitHub.com pull requests page. Also, Pixee [cryptographically signs every commit](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work), which means changes suggested by Pixee are guaranteed to have come from Pixee, were not modified after the fact and are [verified by GitHub](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification).

### You said Pixee supports rule X for language Y, but I don't see a fix available. What gives?

Some "shapes" of vulnerable code may not be fixable in a safe way, or recognized by our remediation logic. Please file a ticket if this happens and you think we should fix it! Providing an anonymized code sample and security finding will help us a lot.

### Where can I learn more and discuss Pixee?

Users can join the Pixee community [on Slack](https://join.slack.com/t/openpixee/shared_invite/zt-1pnk7jqdd-kfwilrfG7Ov4M8rorfOnUA). This channel can be used to engage with peers who are also interested in Pixee. Feel free to email us at help@pixee.ai with any questions or comments.

### Why does pixee sometimes add new dependencies to my project?

We always prefer to use existing controls built into a language, or a control from a well-known and trusted community dependency. When this is not an option, we add our own open source dependency to the project to ensure maximum readability and maintainability. All dependencies utilize permissive open-source licenses.

Learn more about the [Java Security Toolkit (io.github.pixee.java-security-toolkit) on Maven Central](https://central.sonatype.com/artifact/io.github.pixee/java-security-toolkit/overview).

Learn more about the [Python security package on PyPI](https://pypi.org/project/security/).

### How do automatically assign GitHub PR reviewers?

To automatically assign **reviewers** to Pixee PRs, consider [setting up a `CODEOWNERS` file](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners).

To automatically assign **users** to Pixee PRs, consider creating a GitHub action. Below is an example action that will assign all Pixee PRs to the user Octocat:

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


### Configuring Automatic Formatting

Many projects enforce a consistent code style by using automatic code formatters. This section contains instructions for configuring GitHub Actions to automatically format PRs that are created by Pixee.

#### Python

The most popular Python code formatter is [Black](https://black.readthedocs.io/en/stable/). To automatically format PRs created by Pixee using Black, add the following GitHub action workflow to your repository:

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

#### Java

For Java projects it is common to use a tool such as [Spotless](https://github.com/diffplug/spotless) to enforce code formatting. To automatically format PRs created by Pixee using Gradle to apply Spotless, add the following GitHub action workflow to your repository:

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

### How do I configure Lockfile Updates?

Some Pixee fixes add dependencies to your project. For package managers that rely on lockfiles, it is important to update the lockfile after adding dependencies. We recommend using a GitHub Action to automatically update lockfiles for Pixee PRs.

#### Python: Poetry

[Poetry](https://python-poetry.org/) is a popular Python package manager that uses a `pyproject.toml` file to manage dependencies. To automatically update the Poetry lockfile for Pixee PRs that add dependencies, add the following GitHub action workflow to your repository:

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
