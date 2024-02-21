---
title: "Use Safe Parsers in `lxml` Parsing Functions"
sidebar_position: 1
---

## pixee:python/safe-lxml-parsing

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| High       | Merge Without Review | No                     |

This codemod sets the `parser` parameter in calls to  `lxml.etree.parse`  and `lxml.etree.fromstring` if omitted or set to `None` (the default value). Unfortunately, the default `parser=None` means `lxml` will rely on an unsafe parser, making your code potentially vulnerable to entity expansion attacks and external entity (XXE) attacks.

The changes look as follows:

```diff
  import lxml.etree
- lxml.etree.parse("path_to_file")
- lxml.etree.fromstring("xml_str")
+ lxml.etree.parse("path_to_file", parser=lxml.etree.XMLParser(resolve_entities=False))
+ lxml.etree.fromstring("xml_str", parser=lxml.etree.XMLParser(resolve_entities=False))
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

We believe this change is safe, effective, and protects your code against very serious security attacks.

## Codemod Settings

N/A

## References

* [https://lxml.de/apidoc/lxml.etree.html#lxml.etree.XMLParser](https://lxml.de/apidoc/lxml.etree.html#lxml.etree.XMLParser)
* [https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
* [https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
