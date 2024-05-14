---
title: "Replace unsafe `pyyaml` loader with `SafeLoader`"
sidebar_position: 1
---

## pixee:python/harden-pyyaml

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| Medium     | Merge Without Review | No                     |

The default loaders in PyYAML are not safe to use with untrusted data. They potentially make your application vulnerable to arbitrary code execution attacks. If you open a YAML file from an untrusted source, and the file is loaded with the default loader, an attacker could execute arbitrary code on your machine.

This codemod hardens all [`yaml.load()`](https://pyyaml.org/wiki/PyYAMLDocumentation) calls against such attacks by replacing the default loader with `yaml.SafeLoader`. This is the recommended loader for loading untrusted data. For most use cases it functions as a drop-in replacement for the default loader.

Calling `yaml.load()` without an explicit loader argument is equivalent to calling it with `Loader=yaml.Loader`, which is unsafe. This usage [has been deprecated](https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input\)-Deprecation) since PyYAML 5.1. This codemod will add an explicit `SafeLoader` argument to all `yaml.load()` calls that don't use an explicit loader.

The changes from this codemod look like the following:

```diff
  import yaml
  data = b'!!python/object/apply:subprocess.Popen \\n- ls'
- deserialized_data = yaml.load(data, yaml.Loader)
+ deserialized_data = yaml.load(data, Loader=yaml.SafeLoader)
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

This codemod replaces any unsafe loaders with the `SafeLoader`, which is already the recommended replacement suggested in `yaml` documentation. We believe this replacement is safe and should not result in any issues.

## Codemod Settings

N/A

## References

- [https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
- [https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation](<https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation>)
