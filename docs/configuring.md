---
sidebar_position: 3
---

# Configuring

You can configure Pixeebot by creating a YAML file at `.github/pixeebot.yaml.`

A typical configuration file might look like this:
```yaml
assignees: [mary, luis]
```

## `assignees`
Setting this field tells Pixeebot which GitHub collaborators from the repository should be assigned when it sends pull requests to the main branch. The bot will randomly select from the list every time a pull request is issued.

If no assignees are provided through this configuration, a collaborator may be assigned at random. 

To automatically assign reviewers to Pixeebot PRs, consider [setting up a `CODEOWNERS` file](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners).
