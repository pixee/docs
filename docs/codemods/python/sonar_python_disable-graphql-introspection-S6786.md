---
title: "Sonar: Disable GraphQL Introspection to Prevent Sensitive Data Leakage"
sidebar_position: 1
---

## sonar:python/disable-graphql-introspection-S6786

| Importance | Review Guidance    | Requires Scanning Tool |
| ---------- | ------------------ | ---------------------- |
| High       | Merge After Review | Yes (Sonar)            |

This codemod acts upon the following Sonar rules: python:S6786.

Introspection allows a client to query the schema of a GraphQL API. Allowing introspection in production code may allow a malicious user to gather information about data types and operations for a potential attack.

Introspection is often enabled by default in GraphQL without authentication. This codemod disables introspection altogether at the view level by introducing a validation rule. The required rules may be dependent on the framework that you are using. Please check your framework documentation for specific rules for disabling introspection.

Our changes look something like this:

```diff
from graphql_server.flask import GraphQLView
from flask import Flask
from graphql import (
    GraphQLSchema, GraphQLObjectType, GraphQLField, GraphQLString)
+from graphql.validation import NoSchemaIntrospectionCustomRule

schema = GraphQLSchema(
    query=GraphQLObjectType(
        name='RootQueryType',
        fields={
            'hello': GraphQLField(
                GraphQLString,
                resolve=lambda obj, info: 'world')
        }))

app = Flask(__name__)

app.add_url_rule("/api",
    view_func=GraphQLView.as_view(  # Noncompliant
        name="api",
        schema=schema,
+       validation_rules = [NoSchemaIntrospectionCustomRule]
    ),
)
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Review?

This change may disable a feature that was left on purpose. Moreover the rule added may be framework specific.

## Codemod Settings

N/A

## References

- [https://owasp.org/Top10/A05_2021-Security_Misconfiguration/](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)
- [https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL#introspection-queries](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL#introspection-queries)
- [GraphQL introspection should be disabled in production](https://rules.sonarsource.com/python/RSPEC-6786/)
