---
title: Your First Fix
slug: /getting-started/first-fix
track: dev
content_type: tutorial
seo_title: "Your First Pixee Fix | From Install to Merged PR in Minutes"
description: "Walk through your first automated security fix from Pixee: PR contents, diff review, and merge workflow."
sidebar_position: 8
---

Your first Pixee fix arrives as a pull request in your existing code review tool. Open the PR, read the description, review the diff, and merge. Most teams see their first fix within an hour of installation. This page walks through exactly what that PR looks like and how to evaluate it.

## What to Expect

After installing Pixee ([GitHub](/getting-started/github), [GitLab](/getting-started/gitlab), [Azure DevOps](/getting-started/azure-devops), or [Bitbucket](/getting-started/bitbucket)), the platform connects to your repositories, ingests findings, and begins triaging. For confirmed vulnerabilities with available fixes, Pixee opens a pull request.

First PRs are not random. Pixee prioritizes high-confidence, low-risk fixes for initial pull requests — deterministic codemods with predictable behavior. The first fix establishes trust through a clear, reviewable change, not through volume.

## Anatomy of a Pixee Fix PR

Every Pixee PR includes a descriptive title, a structured description, and the diff.

**PR Title:** Identifies the vulnerability type and affected file. Example: `Pixee fix: Parameterize SQL query in UserRepository.java`

**PR Description — four parts:**

1. **The vulnerability** — What was found, which scanner flagged it, severity, CWE, and OWASP category.
2. **The fix** — What Pixee changed and why this approach was chosen.
3. **Safety evidence** — Why the fix is safe. For codemods: rule-based transformation with no behavioral change. For MagicMods: validation scores from the fix evaluation pipeline.
4. **References** — CWE definitions, OWASP documentation, scanner rule links.

**The Diff:** Typically 1-5 lines in a single file. One vulnerability per PR — no bundled changes or surrounding refactors.

## Reviewing the Fix

Review a Pixee PR the same way you review any other code change:

**Step 1: Read the PR description.** Understand the vulnerability and how the fix resolves it.

**Step 2: Review the diff.** Confirm the code change is correct for your application.

**Step 3: Check CI results.** Your existing tests, linters, and scanners run against the fix automatically. If tests pass, the fix does not break existing behavior.

**Step 4: Decide:**

| Action              | When                                                                                  |
| ------------------- | ------------------------------------------------------------------------------------- |
| **Merge**           | The fix is correct, tests pass, and the change resolves the vulnerability             |
| **Request changes** | The fix is directionally correct but needs modification for your codebase conventions |
| **Close**           | The fix is not appropriate for your codebase or the finding is acceptable risk        |

Pixee proposes. You decide. This is assisted remediation through your existing review process.

## Common First-Fix Scenarios

**SQL injection fix:** Pixee replaces string concatenation with a parameterized query.

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

**Dependency upgrade (SCA fix):** Pixee bumps a vulnerable dependency to a patched version. The change is a single line in your manifest file (`pom.xml`, `requirements.txt`, `package.json`). Pixee checks for breaking changes before proposing the upgrade.

**Hardcoded secret removal:** Pixee extracts a hardcoded credential into an environment variable reference. The code changes from a string literal to an environment variable lookup, and the PR description notes which variable to set.

## After You Merge

Once you merge, the vulnerability is resolved. Your scanner confirms remediation on its next run, your backlog shrinks by one, and Pixee continues generating fixes for other findings. No dashboard to update, no ticket to close. The merged PR is the record.

**Metrics to watch:**

| Metric            | What It Tells You                                                                                              |
| ----------------- | -------------------------------------------------------------------------------------------------------------- |
| Merge rate        | What percentage of Pixee PRs your team accepts. See [Fix Safety](/how-it-works/fix-safety) for benchmark data. |
| Time to merge     | How quickly your team reviews and merges fixes                                                                 |
| Backlog reduction | How fast your open vulnerability count decreases                                                               |

## What If No Fix Arrives?

If you do not see a PR within an hour of installation:

1. **Verify the integration is connected.** Check that Pixee has access to the repositories you selected during setup.
2. **Confirm supported languages are present.** Pixee supports Java, Python, JavaScript/TypeScript, .NET, Go, and PHP. Repositories in other languages will not generate fixes.
3. **Connect a scanner.** Pixee generates more fixes when it has scanner findings to work from. Connect CodeQL, Semgrep, SonarQube, or any SARIF-producing scanner via [CI/CD Integration](/getting-started/ci-cd).
4. **Check for fixable findings.** Your repositories may have findings that Pixee cannot currently remediate. This does not mean the integration is broken — it means the specific vulnerability types present do not yet have available codemods or MagicMod coverage.

## From First Fix to Full Value

The first merged fix proves the workflow: setup takes minutes, fixes arrive without manual effort, and developers stay in their existing tools.

- **Connect additional scanners** to expand coverage. Pixee works with 12 natively integrated scanners and any SARIF-producing tool.
- **Roll out to more repositories** as confidence builds.
- **Track your merge rate.** See [Fix Safety](/how-it-works/fix-safety) for merge rate data.

For scaling from a single repository to organization-wide deployment, see the [Phased Rollout Guide](/enterprise/phased-rollout). For technical depth on fix methodology, see [Fix Generation](/how-it-works/fix-generation) and [Fix Safety and Validation](/how-it-works/fix-safety).

## Frequently Asked Questions

### How do I get my first automated fix from Pixee?

Install Pixee for your platform ([GitHub](/getting-started/github), [GitLab](/getting-started/gitlab), [Azure DevOps](/getting-started/azure-devops), or [Bitbucket](/getting-started/bitbucket)), connect at least one repository, and wait for your first pull request. Most teams receive their first fix within an hour of installation.

### How long does it take to review a Pixee fix?

Most fixes change 1-5 lines and take seconds to minutes to review. The PR description explains the vulnerability, the fix approach, and why it is safe.

### What if I disagree with a Pixee fix?

Close the PR or leave a comment requesting changes — the same workflow as any other code review. Pixee proposes fixes; your team decides which to merge. You maintain full control over your codebase.

### Are Pixee fixes deterministic or AI-generated?

Both. Pixee uses deterministic codemods for well-understood vulnerability patterns -- these produce identical, predictable output every time. For complex, codebase-specific scenarios, Pixee uses MagicMods (AI-generated fixes) that pass through a validation pipeline scoring Safety, Effectiveness, and Cleanliness before reaching your PR queue. See [Fix Generation](/how-it-works/fix-generation) for details on the codemod library.
