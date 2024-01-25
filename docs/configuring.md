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

## Configuring Automatic Assignment

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
