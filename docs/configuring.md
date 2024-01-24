---
sidebar_position: 3
---

# Configuring

There are two approaches to configuring Pixeebot:

1. **Target Repository Configuration:**
   Create a `pixeebot.yaml` file in the `.github` directory of the target repository. Configurations in the target repository will take precedence over other configurations.

2. **Global Repository Configuration:**
   Alternatively, you can create the `pixeebot.yaml` file in the `.github` directory of your `.github` repository. This will serve as a global configuration that applies to multiple repositories.

## YAML

A typical .yaml configuration file might look like this:

```yaml
activity_dashboard: true

ai:
  allow_llm_access: true
```

## Properties

### `activity_dashboard`
The activity dashboard exists as a GitHub Issue and offers a holistic perspective on Pixeebot's functionality within your repository. Through this interface, you can conveniently monitor open pull requests, pending recommendations, and more. The dashboard is automatically triggered upon installation, provided that GitHub Issues are enabled for your repository. Setting to `false` will remove it from view. 

### `ai`

Contains settings related to AI functionality. 

#### `allow_llm_access`

Setting to `true` will enable Pixeebot to [send data to a LLM](faqs.md) while analyzing your code.

> **Note** This is the default configuration upon installation.

# Configuring Automatic Assignment

To automatically assign reviewers to pixeebot PRs, consider [setting up a `CODEOWNERS` file](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners).

To automatically assign users to pixeebot PRs, consider creating a github action. Below is an example action that will assign all pixeebot PRs to the user octocat:

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

Please contact us at help@pixee.ai if you have any questions, or would like more options for automatic assignment.
