---
title: Custom Codemods
slug: /open-source/custom-codemods
track: dev
content_type: tutorial
seo_title: Custom Codemods -- Pixee Docs
description: Build custom security codemods using the Codemodder framework. Step-by-step tutorial for Java and Python.
sidebar_position: 3
---

# Custom Codemods

You can build custom codemods using Pixee's open source [Codemodder](/open-source/codemodder) framework to automate security fixes specific to your organization's codebase patterns. Custom codemods are deterministic transformation rules -- same input, same output, every time. This tutorial walks through building a custom codemod from scratch: defining the detection pattern, writing the transformation, testing it, and deploying it.

## When to Build Custom Codemods

The built-in codemods cover common vulnerability patterns from OWASP and SANS (see [Codemodder](/open-source/codemodder) for the full catalog). Custom codemods make sense when:

- **Your organization has internal security patterns.** You enforce coding standards that go beyond public vulnerability databases. Maybe your team requires all HTTP clients to use an internal `SecureHttpClient` wrapper, or all database access to go through a custom query builder.
- **You use internal frameworks.** Your codebase has framework-specific utilities (e.g., a custom `SafeQueryBuilder` or `AuthenticatedRequestFactory`) that the built-in codemods do not know about.
- **You want auditable, repeatable fixes.** Rather than manually fixing the same pattern across hundreds of files, a codemod applies the same transformation everywhere, consistently and testably.
- **You want to contribute back.** If the pattern is general enough, you can submit your codemod to the open source repositories for the community.

## Prerequisites

**For Java codemods:**

- JDK 17 or later
- Gradle (the codemodder-java build system)
- Familiarity with Java AST concepts (abstract syntax trees)

**For Python codemods:**

- Python 3.10 or later
- pip for dependency management
- Familiarity with LibCST or basic regex patterns

**For both:**

- A working understanding of the [Codemodder](/open-source/codemodder) architecture
- The vulnerability pattern you want to detect and the fix you want to apply

## Tutorial: Build a Custom Java Codemod

This example builds a codemod that detects direct `Statement.execute()` calls with user-controlled input and transforms them into parameterized `PreparedStatement` queries.

### Step 1: Set Up the Development Environment

```bash
# Clone the repository
git clone https://github.com/pixee/codemodder-java.git
cd codemodder-java
```

Review the project structure. Codemods live in the `core-codemods/` directory. Each codemod is a single class that extends the framework's base codemod class and registers itself for a specific vulnerability pattern.

### Step 2: Define the Detection Pattern

Before writing code, define clearly what the codemod detects and what it produces.

**Vulnerable input (before):**

```java
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = connection.createStatement();
stmt.execute(query);
```

**Secure output (after):**

```java
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setString(1, userId);
stmt.execute();
```

The codemod needs to:

1. Find `Statement.execute()` calls where the query string is built via concatenation
2. Replace the `Statement` with `PreparedStatement`
3. Extract concatenated variables into parameterized placeholders
4. Add the corresponding `setParameter()` calls

### Step 3: Write the Transformation

Implement the codemod class by extending the framework's base class. The class declares which CWE or rule ID it handles, and the `visit` method contains the transformation logic.

The transformation uses ParseAndGo to walk the Java AST, identify `Statement.execute()` nodes, and rewrite them. The framework handles file discovery, change tracking, and structured-report generation.

Refer to the [codemodder-java CONTRIBUTING guide](https://github.com/pixee/codemodder-java/blob/main/CONTRIBUTING.md) for the current base class interfaces and registration patterns.

### Step 4: Add Tests

Every codemod requires before/after test fixtures:

**Test fixture: `before/SqlInjection.java`**

```java
// Contains the vulnerable code pattern
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = connection.createStatement();
stmt.execute(query);
```

**Test fixture: `after/SqlInjection.java`**

```java
// Contains the expected secure code after transformation
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setString(1, userId);
stmt.execute();
```

The test framework automatically runs the codemod against the `before` fixture and asserts the output matches the `after` fixture. Add multiple test cases covering:

- The primary pattern (direct string concatenation)
- Variations in code style (different variable names, multi-line queries)
- Edge cases (multiple concatenated variables, nested expressions)
- Cases where the codemod should NOT transform (already parameterized queries)

### Step 5: Register the Codemod

Add the codemod to the registration system so the engine discovers it at runtime. Registration maps the codemod to its CWE identifier and assigns it a unique codemod ID (e.g., `pixee:java/sql-parameterizer`).

### Step 6: Run and Validate

```bash
# Build the project with the new codemod
./gradlew build

# Run against a test repository
./gradlew run --args="--source /path/to/test-repo --codemod-include pixee:java/sql-parameterizer --output results.json"
```

Review the report in `results.json` to verify the changes are correct. The output describes each file modified, the lines changed, and the security rationale.

## Tutorial: Build a Custom Python Codemod

Python codemods follow the same pattern with different tooling. This example builds a codemod that detects `yaml.load()` without a safe loader and transforms it to `yaml.safe_load()`.

### Step 1: Set Up the Development Environment

```bash
# Clone the repository
git clone https://github.com/pixee/codemodder-python.git
cd codemodder-python
pip install -e ".[dev]"
```

### Step 2: Define the Detection Pattern

**Vulnerable input (before):**

```python
import yaml

with open("config.yml") as f:
    config = yaml.load(f)
```

**Secure output (after):**

```python
import yaml

with open("config.yml") as f:
    config = yaml.safe_load(f)
```

### Step 3: Choose a Transformer Strategy

Python codemods support three transformer strategies:

| Strategy   | When to Use                                                                  | This Example                                         |
| ---------- | ---------------------------------------------------------------------------- | ---------------------------------------------------- |
| **LibCST** | Transforming Python source code (function calls, imports, class definitions) | Yes -- rewriting `yaml.load()` to `yaml.safe_load()` |
| **Regex**  | Simple pattern replacements in config files or source                        | Not for this example                                 |
| **XML**    | Modifying XML configuration or manifest files                                | Not for this example                                 |

For this codemod, LibCST is the right choice because we are transforming a Python function call.

### Step 4: Write the Transformation

The codemod class extends the Python framework's base class and uses LibCST to locate `yaml.load()` calls and replace them with `yaml.safe_load()`. The framework handles file traversal, change tracking, and output generation.

Refer to the [codemodder-python CONTRIBUTING guide](https://github.com/pixee/codemodder-python/blob/main/CONTRIBUTING.md) for the current base class interfaces and visitor patterns.

### Step 5: Add Tests and Register

Create before/after test fixtures following the same pattern as Java. Register the codemod with a unique ID (e.g., `pixee:python/safe-yaml-load`).

### Step 6: Run and Validate

```bash
# Run against a test repository
codemodder /path/to/test-repo --codemod-include pixee:python/safe-yaml-load --output results.json
```

## Testing Best Practices

Reliable codemods require thorough testing:

- **Before/after fixtures are mandatory.** Every codemod must have at least one fixture pair demonstrating the transformation.
- **Cover style variations.** Real codebases are messy. Test with different indentation, variable naming, multi-line expressions, and comment placement.
- **Test negative cases.** Include fixtures where the codemod should NOT transform code. A codemod that triggers false positives erodes trust.
- **Edge cases matter.** What happens with nested function calls? What about files with multiple instances of the pattern? What about partial matches?
- **Run against real repositories.** After unit tests pass, run the codemod against an actual codebase to validate behavior at scale.

## Deploying Custom Codemods

**Local and CI/CD.** Custom codemods run anywhere Codemodder runs. Add them to your CI/CD pipeline to enforce organization-specific security patterns on every commit:

```bash
# Example CI/CD step
codemodder $WORKSPACE --codemod-include pixee:python/safe-yaml-load --output results.json
```

**Sharing across teams.** Package custom codemods as a separate module that depends on the Codemodder framework. Teams can pull your codemod package alongside the core engine.

**Contributing upstream.** If your codemod addresses a general vulnerability pattern, consider [contributing it back](/open-source/contributing) to the open source repositories so the broader community benefits.

