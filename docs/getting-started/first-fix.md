---
title: Your First Fix
slug: /getting-started/first-fix
track: dev
content_type: tutorial
seo_title: "Your First Pixee Fix | From Install to Merged PR"
description: "What a Pixee PR looks like, what the quality scores mean, and what to do with it."
sidebar_position: 6
---

Your first Pixee fix arrives as a pull request in your existing code review tool. This page covers what to expect, how to evaluate the fix, and what the quality scores mean.

## Anatomy of a Pixee Fix PR

**PR Title:** Identifies the vulnerability type and affected file. Example: `Pixee fix: Parameterize SQL query in UserRepository.java`

**PR Description — four parts:**

1. **The vulnerability** — What was found, which scanner flagged it, severity, CWE, and OWASP category.
2. **The fix** — What Pixee changed and why this approach was chosen.
3. **Quality scores** — Safety, Effectiveness, and Cleanliness scores from the independent evaluation gate.
4. **References** — CWE definitions, OWASP documentation, scanner rule links.

**The Diff:** Typically 1-5 lines in a single file. One vulnerability per PR — no bundled changes or surrounding refactors.

## Understanding the Quality Scores

Every Pixee PR includes three scores from an independent evaluation pass (a separate inference call from the fix generator):

| Score | What It Checks |
|---|---|
| **Safety** | No breaking changes, no regressions, no unintended side effects |
| **Effectiveness** | The fix correctly resolves the vulnerability |
| **Cleanliness** | Proper formatting, no extraneous changes, preserves existing code |

All three must pass before the fix reaches your PR queue. A fix cannot reach you on a high Cleanliness score if it fails Safety.

## What to Do With the PR

Review a Pixee PR the same way you review any other code change:

1. Read the PR description — understand the vulnerability and the fix approach.
2. Review the diff — confirm the code change is correct for your application.
3. Check CI results — your existing tests, linters, and scanners run against the fix automatically.
4. Decide:

| Action | When |
|---|---|
| **Merge** | The fix is correct, tests pass, and the change resolves the vulnerability |
| **Request changes** | The fix is directionally correct but needs modification for your codebase conventions |
| **Close** | The fix is not appropriate for your codebase or the finding is acceptable risk |

Pixee proposes. You decide. Your code review policies, CI/CD pipelines, and branch protection rules all apply.

## Example Fixes

**SQL injection — Java:**

```java
// Before
String query = "SELECT * FROM users WHERE id = '" + userId + "'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);

// After (Pixee fix)
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = conn.prepareStatement(query);
stmt.setString(1, userId);
ResultSet rs = stmt.executeQuery();
```

**Dependency upgrade (SCA fix):** Pixee bumps a vulnerable dependency to a patched version in your manifest file (`pom.xml`, `requirements.txt`, `package.json`) and includes any downstream source-file changes in the same PR.

## After You Merge

Once you merge, the vulnerability is resolved. Your scanner confirms remediation on its next run, and your backlog shrinks. No dashboard to update, no ticket to close. The merged PR is the record.

Standard `git revert` applies if a merged change ever needs to be undone. There is no runtime dependency on Pixee for merged code.

## If No Fix Arrives

If you do not see a PR within an hour of installation:

1. **Verify the integration is connected.** Check that Pixee has access to the repositories you selected during setup.
2. **Confirm a scanner is connected.** Pixee needs scanner findings to act on. Connect CodeQL, Semgrep, SonarQube, or any SARIF-producing scanner via [CI/CD Integration](/integrations/ci-cd).
3. **Confirm supported languages are present.** Repositories in unsupported languages will not generate fixes.
4. **Check for fixable findings.** Your repositories may have findings that Pixee cannot currently remediate. Triage classifications will still appear.

## From First Fix to Full Value

Once the workflow is proven:

- **Connect additional scanners** to expand coverage. Pixee works with natively integrated scanners and any SARIF-producing tool.
- **Roll out to more repositories** as confidence builds.
- **Track your merge rate** — see [Security & Trust](/platform/security) for merge rate data and context.

For scaling to organization-wide deployment, see the [Phased Rollout Guide](/enterprise/phased-rollout). For technical depth on fix methodology, see [Remediation](/platform/remediation).
