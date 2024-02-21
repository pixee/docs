---
title: "Use `typ='safe'` in ruamel.yaml() Calls"
sidebar_position: 1
---

## pixee:python/harden-ruamel

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| Medium     | Merge Without Review | No                     |

This codemod hardens any unsafe [`ruamel.yaml.YAML()`](https://yaml.readthedocs.io/en/latest/) calls against attacks that could result from deserializing untrusted data.

The fix uses a safety check that already exists in the `ruamel` module, replacing an unsafe `typ` argument with `typ="safe"`.
The changes from this codemod look like this:

```diff
  from ruamel.yaml import YAML
- serializer = YAML(typ="unsafe")
- serializer = YAML(typ="base")
+ serializer = YAML(typ="safe")
+ serializer = YAML(typ="safe")
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

This codemod replaces any unsafe `typ` argument with `typ='safe'`, which makes safety explicit and is one of the recommended uses suggested in `ruamel` documentation. We believe this replacement is safe and should not result in any issues.

## Codemod Settings

N/A

## References

* [https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
