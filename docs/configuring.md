---
sidebar_position: 3
---

# Configuring

To configure Pixeebot, you have two options:
1. **Target Repository Configuration**: Place a `pixeebot.yaml` file in the `.github` firectory of the target repoository. Configurations in the target repository will take precendenc over other configurations.
2. **Global Repository Configuration**: Alternatively, you can place the `pixeebot.yaml` file in the `.github` directory of your `.github` repository. This will serve as a global configuration that applies to multiple repositories.

> ⚠️ You must grant access to the `.github` repository for Global Repository Configuration to work 


A typical configuration file might look like this:
```yaml
assignees: [mary, luis]
```

## `assignees`
Setting this field tells Pixeebot which GitHub collaborators from the repository should be assigned when it sends pull requests to the main branch. The bot will randomly select from the list every time a pull request is issued.

If no assignees are provided through this configuration, a collaborator may be assigned at random. 

To automatically assign reviewers to Pixeebot PRs, consider [setting up a `CODEOWNERS` file](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners).
