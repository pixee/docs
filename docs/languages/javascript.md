---
title: JavaScript / TypeScript
slug: /languages/javascript
track: both
content_type: guide
seo_title: JavaScript / TypeScript Language Support -- Pixee Docs
description: "Pixee JavaScript/TypeScript support: deterministic codemods and AI-powered fixes for Express, React, and Node.js."
sidebar_position: 4
---

Pixee remediates JavaScript and TypeScript vulnerabilities automatically using deterministic codemods and AI-powered fixes. Coverage spans Express, React, and Node.js applications with fixes for injection vulnerabilities, prototype pollution, insecure dependencies, and OWASP Top 10 patterns. Pixee uses full AST analysis for deep cross-file dataflow tracking and manages package.json dependency upgrades coordinated with source-file refactoring in a single pull request.

JavaScript/TypeScript support is actively expanding. Deterministic codemod coverage is growing alongside comprehensive AI-powered MagicMod support. For the full language coverage matrix, see the [Language Support Overview](/languages/overview).

## What Pixee Fixes in JavaScript/TypeScript

| Vulnerability Type        | CWE      | Example Fix                                 | Fix Mode         |
| ------------------------- | -------- | ------------------------------------------- | ---------------- |
| SQL Injection             | CWE-89   | Parameterized query conversion              | Deterministic/AI |
| Cross-Site Scripting      | CWE-79   | Output encoding, template sanitization      | Deterministic/AI |
| Prototype Pollution       | CWE-1321 | Object.freeze, safe merge patterns          | AI-powered       |
| SSRF                      | CWE-918  | URL validation and allowlist enforcement    | Deterministic/AI |
| Path Traversal            | CWE-22   | Canonical path validation                   | Deterministic/AI |
| Weak Cryptography         | CWE-327  | crypto.randomBytes, secure defaults         | Deterministic/AI |
| Insecure Dependencies     | N/A      | npm/yarn version upgrades + source refactor | Hybrid           |
| Custom Framework Patterns | Various  | Framework-specific sanitization             | AI-powered       |

## Node.js and Express

Node.js applications running Express are the most common server-side JavaScript pattern Pixee encounters. Pixee provides targeted support for Express-specific security concerns.

**What Pixee understands about your Express code:**

- Route handler patterns (`app.get`, `app.post`, `router.use`) and parameter extraction
- Middleware chains, including authentication and validation middleware ordering
- Request object handling (`req.params`, `req.query`, `req.body`) and injection vectors
- Express-specific session management and cookie configuration

**Express-specific fixes include:**

- SQL injection remediation in database query builders (Knex, Sequelize, raw queries)
- Input validation for Express request parameters that flow into sensitive operations
- Middleware security hardening (helmet configuration, CORS policy, rate limiting)
- Cookie and session configuration fixes (httpOnly, secure, sameSite flags)

**Node.js crypto module hardening:** Pixee identifies and fixes insecure cryptographic patterns including `Math.random()` for tokens (replaced with `crypto.randomBytes`), weak hash algorithms, and insecure cipher configurations.

## TypeScript Support

Pixee analyzes TypeScript files with full type awareness. Fixes preserve type annotations, generic type parameters, and interface contracts. When Pixee generates a fix for a TypeScript file, the result compiles cleanly with your existing `tsconfig.json` settings.

This matters because many tools treat TypeScript as plain JavaScript and strip type annotations during fix generation. Pixee treats `.ts` and `.tsx` files as first-class targets.

## React and Frontend Frameworks

Pixee addresses React-specific security patterns on the server side and in server-rendered contexts:

- **dangerouslySetInnerHTML patterns:** Pixee identifies and remediates XSS risks from unsanitized HTML injection in React components
- **Server-side rendering (SSR):** Fixes cover injection vulnerabilities in Next.js and other SSR frameworks where server-side data flows into rendered HTML
- **Client-side scope:** Pixee's primary focus is server-side vulnerabilities. Client-side-only patterns (e.g., React state management) are not in scope for automated remediation

If your security concern is a server-side JavaScript vulnerability, Pixee covers it. Pure client-side browser security patterns are outside Pixee's current focus.

## How It Works for JavaScript/TypeScript

**Analysis depth:** Full AST parsing with cross-file dataflow analysis. Pixee follows taint propagation from Express route handlers through middleware chains to database calls and response rendering.

**Fix routing:** When a scanner finding matches a deterministic codemod, the fix fires instantly with zero LLM cost. Novel or custom patterns route to AI-powered MagicMods, which receive JavaScript/TypeScript-specific context including framework detection, dependency analysis, and your PIXEE.yaml configuration.

**Dependency support:** Pixee manages vulnerable packages in package.json (npm, yarn). A single pull request contains the version bump and any source-file changes required by the upgrade, such as updated import paths or changed API signatures.

**Scanner compatibility:** MagicMod dispatchers for 8+ scanner types mean JavaScript/TypeScript findings from any supported scanner receive appropriate, scanner-aware context during fix generation.

## Fix Examples

**SQL Injection (CWE-89) -- Express Route Handler**

Before:

```javascript
app.get("/users", (req, res) => {
  const userId = req.query.id;
  db.query(`SELECT * FROM users WHERE id = '${userId}'`, (err, results) => {
    res.json(results);
  });
});
```

After:

```javascript
app.get("/users", (req, res) => {
  const userId = req.query.id;
  db.query("SELECT * FROM users WHERE id = ?", [userId], (err, results) => {
    res.json(results);
  });
});
```

**Weak Cryptography (CWE-327) -- Secure Token Generation**

Before:

```javascript
const token = Math.random().toString(36).substring(2);
```

After:

```javascript
const crypto = require("crypto");
const token = crypto.randomBytes(24).toString("hex");
```

**Dependency Upgrade -- Vulnerable npm Package**

Pixee upgrades the vulnerable package version in package.json and includes any source-file changes required by the new version in the same pull request. If the upgrade includes breaking API changes, the PR addresses those changes across affected files.

## Scanner Compatibility

| Scanner         | JS/TS Support |
| --------------- | ------------- |
| CodeQL          | Yes           |
| Semgrep         | Yes           |
| SonarQube       | Yes           |
| Snyk Code       | Yes           |
| Universal SARIF | Yes           |

npm audit findings can be exported in SARIF format and consumed through the [universal SARIF integration](/integrations/sarif-universal).

## Compatibility

| Dimension            | Details                                                      |
| -------------------- | ------------------------------------------------------------ |
| Package managers     | npm, yarn                                                    |
| CI/CD platforms      | GitHub Actions, GitLab CI, Azure DevOps, Bitbucket Pipelines |
| Code hosting         | GitHub, GitLab, Azure DevOps, Bitbucket                      |
| Dependency manifests | package.json                                                 |
| Frameworks           | Express, React, Next.js, Node.js standard library            |

