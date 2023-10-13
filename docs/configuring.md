---
sidebar_position: 3
---

# Configuring

There are two approaches to configuring Pixeebot:

1. **Target Repository Configuration**: Create a `pixeebot.yaml` file in the `.github` directory of the target repoository. Configurations in the target repository will take precendence over other configurations.
2. **Global Repository Configuration**: Alternatively, you can create the pixeebot.yaml file in the .github directory of your .github repository. This will serve as a global configuration that applies to multiple repositories


A typical configuration file might look like this:
```yaml
assignees: [mary, luis]
```

## `assignees`
Setting this field tells Pixeebot which GitHub collaborators from the repository should be assigned when it sends pull requests to the main branch. The bot will randomly select from the list every time a pull request is issued.

If no assignees are provided through this configuration, a collaborator may be assigned at random. 

To automatically assign reviewers to Pixeebot PRs, consider [setting up a `CODEOWNERS` file](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners).
