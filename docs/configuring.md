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
ai:
  allow_llm_access: true
```

## Properties

### `ai`

Contains settings related to AI functionality

#### `allow_llm_access`

Setting to `true` will enable Pixeebot to [send data to a LLM](faqs.md) while analyzing your code

> **Note** This is the default configuration upon installation.

# Configuring Automatic Assignment

To automatically assign reviewers to pixeebot PRs, consider [setting up a `CODEOWNERS` file](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners).

To automatically assign users to pixeebot PRs, consider creating a github action. Below is an example action that will assign all pixeebot PRs to the user octocat:

```yaml
name: Assign pixeebot PRs to octocat

on:
  pull_request_target:
    types: [opened, ready_for_review]

jobs:
  assign-to-me:
    runs-on: ubuntu-latest

    steps:
      - name: Check out repository
        uses: actions/checkout@v2

      - name: Assign pixeebot PRs to octocat
        run: |
          # Check if the PR is opened by pixeebot
          if [[ "${{ github.event.pull_request.user.login }}" == "pixeebot[bot]" ]]; then
            # Assign the PR to octocat
            echo "Assigning PR to octocat..."
            gh pr edit ${{ github.event.pull_request.number }} --add-assignee "octocat"
          else
            echo "PR is not opened by pixeebot. No action needed."
          fi
        env:
          GITHUB_TOKEN: ${{ secrets.GH_TOKEN }}
```

Please contact us at help@pixee.ai if you have any questions, or would like more options for automatic assignment.
