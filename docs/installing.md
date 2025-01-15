---
sidebar_position: 2
---

# Installing

Pixee is available as a GitHub App on the [GitHub Marketplace](https://github.com/apps/pixeebot/).
We provide a free tier offering that can be installed on any public or private repository. This is a great way to get started with Pixee and see how it can help to harden and secure your code.

To try Pixee, visit our [GitHub App page](https://github.com/apps/pixeebot/). From there, click **Install** (or **Configure**) and follow the prompts from GitHub. You'll be directed to your Pixee dashboard once the installation process is complete.

See the [Preferences](/configuring) page for information on how to configure Pixee to suit your needs.

## Self-Hosted

Pixee offers a self-hosted Pixee Enterprise Server for organizations that require additional security or compliance measures. To learn more about Pixee self-hosted solutions, please [contact us](https://pixee.ai/demo-landing-page).

Also [contact us](https://pixee.ai/demo-landing-page) if you want to partner as early customers for other SCMs, including GitLab, Bitbucket, or Azure DevOps.

## Tool connections

Pixee fixes problems detected by [your existing code scanning tools and services](/code-scanning-tools/overview).

If you use GitHub Advanced Security (GHAS), then installing the Pixeebot GitHub App is sufficient for connecting Pixee to your GHAS results.

Otherwise, you will need to connect Pixee to your code scanning tools and services, before Pixee can send fixes. If your repository does not use any code scanning tools and services, but you still want to try Pixee, see our guide for [adding Semgrep CLI and Pixee to your GitHub repository](./code-scanning-tools/semgrep.md).

## Repository access

During installation, you’ll need to specify which of your repositories Pixee can access. This can be done in one of two ways:

- **All repositories -** By selecting this option, Pixee will monitor all your existing and future repositories.
- **Select repositories -** Opting for this choice will present you with a list of your current repositories. From there, you can choose the specific repositories Pixee can access.

## Updating repository access

To update repository access for Pixee:

**From Pixee Dashboard:**

- Click the "+Add installation" link at the bottom of your Installations page.

**From GitHub:**

- Go to your GitHub homepage.
- Navigate to Settings > Integrations > Applications.
- Select "pixeebot" from the list of applications.
- Click the configure button to access Pixee settings.

Repository access selection can be managed at any time by adjusting settings through either of these paths.

<iframe width="100%" height="315" src="https://www.youtube.com/embed/0p6nbDUrfeE?si=BJM0CAGc8zoJF26E" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>
