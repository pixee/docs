---
title: Use SafeLoader in `yaml.load()` Calls
sidebar_position: 1
---

## pixee:python/harden-pyyaml

| Importance | Review Guidance            | Requires SARIF Tool |
|------------|----------------------------|---------------------|
| Medium       | Merge Without Review | No                  |

This codemod hardens all [`yaml.load()`](https://pyyaml.org/wiki/PyYAMLDocumentation) calls against attacks that could result from deserializing untrusted data.

The fix uses a safety check that already exists in the `yaml` module, replacing unsafe loader class with `SafeLoader`.
The changes from this codemod look like this:

```diff
  import yaml
  data = b'!!python/object/apply:subprocess.Popen \\n- ls'
- deserialized_data = yaml.load(data, yaml.Loader)
+ deserialized_data = yaml.load(data, Loader=yaml.SafeLoader)
```
The codemod will also catch if you pass in the loader argument as a kwarg and if you use any loader other than `SafeLoader`,
including `FullLoader` and `UnsafeLoader`.

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

This codemod replaces any unsafe loaders with the `SafeLoader`, which is already the recommended replacement suggested in `yaml` documentation. We believe this replacement is safe and should not result in any issues.

## Codemod Settings

N/A

## References

* [https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
