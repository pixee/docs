---
title: "Use `defusedxml` for Parsing XML"
sidebar_position: 1
---

## pixee:python/use-defusedxml

| Importance | Review Guidance    | Requires Scanning Tool |
| ---------- | ------------------ | ---------------------- |
| High       | Merge After Review | No                     |

You might be surprised to learn that Python's built-in XML libraries are [considered insecure](https://docs.python.org/3/library/xml.html#xml-vulnerabilities) against various kinds of attacks.

In fact, the [Python documentation itself](https://docs.python.org/3/library/xml.html#the-defusedxml-package) recommends the use of [defusedxml](https://pypi.org/project/defusedxml/) for parsing untrusted XML data. `defusedxml` is an [open-source](https://github.com/tiran/defusedxml), permissively licensed project that is intended as a drop-in replacement for Python's standard library XML parsers.

This codemod updates all relevant uses of the standard library parsers with safe versions from `defusedxml`. It also adds the `defusedxml` dependency to your project where possible.

The changes from this codemod look like this:

```diff
- from xml.etree.ElementTree import parse
+ import defusedxml.ElementTree

- et = parse('data.xml')
+ et = defusedxml.ElementTree.parse('data.xml')
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Review?

We believe this change is safe and effective and guards against serious XML vulnerabilities. You should review this code before merging to make sure the dependency has been properly added to your project.

## Codemod Settings

N/A

## References

- [https://docs.python.org/3/library/xml.html#xml-vulnerabilities](https://docs.python.org/3/library/xml.html#xml-vulnerabilities)
- [https://docs.python.org/3/library/xml.html#the-defusedxml-package](https://docs.python.org/3/library/xml.html#the-defusedxml-package)
- [https://pypi.org/project/defusedxml/](https://pypi.org/project/defusedxml/)
- [https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
