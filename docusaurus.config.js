// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const lightCodeTheme = require("prism-react-renderer").themes.github;
const darkCodeTheme = require("prism-react-renderer").themes.dracula;

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: "Pixee",
  tagline: "Pixee is your automated product security engineer", //TODO: We need a tag line!
  url: "https://docs.pixee.ai",
  baseUrl: "/",
  onBrokenLinks: "throw",
  onBrokenMarkdownLinks: "warn",
  favicon: "img/favicon.ico",

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: "pixee", // Usually your GitHub org/user name.
  projectName: "internal-docs", // Usually your repo name.
  deploymentBranch: "main",

  // Even if you don't use internalization, you can use this field to set useful
  // metadata like html lang. For example, if your site is Chinese, you may want
  // to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },

  stylesheets: [
    "https://fonts.googleapis.com/css2?family=Poppins:wght@300;700&display=swap",
    "https://fonts.googleapis.com/css?family=Source+Sans+Pro:200,200i,300,300i,400,400i,600,600i,700,700i,900,900i&display=swap",
  ],

  presets: [
    [
      "@docusaurus/preset-classic",
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: require.resolve("./sidebars.js"),
          routeBasePath: "/",
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl: "https://github.com/pixee/docs/edit/main/",
        },
        blog: {
          showReadingTime: true,
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl: "https://github.com/pixee/docs/edit/main/",
        },
        theme: {
          customCss: require.resolve("./src/css/custom.css"),
        },
        gtag: {
          trackingID: "G-1M7HM648QD",
          anonymizeIP: true,
        },
        googleTagManager: {
          containerId: "GTM-TSNFBTV",
        },
      }),
    ],
  ],

  plugins: [
    [
      "@docusaurus/plugin-client-redirects",
      {
        redirects: [
          // Old top-level pages → new IA
          { from: "/intro", to: "/" },
          { from: "/installing", to: "/" },
          { from: "/faqs", to: "/faq/general" },
          { from: "/languages", to: "/languages/overview" },
          { from: "/open-pixee", to: "/open-source/overview" },
          {
            from: "/running_on_public_github_repos",
            to: "/getting-started/github",
          },
          { from: "/supported-scms", to: "/" },
          { from: "/using-pixeebot", to: "/getting-started/github" },
          { from: "/getting-started", to: "/" },
          {
            from: "/configuration/scheduling",
            to: "/configuration/operations",
          },
          { from: "/api/codetf", to: "/api/overview" },

          // Old code-scanning-tools/* → new integrations/scanners/*
          {
            from: "/code-scanning-tools/overview",
            to: "/integrations/overview",
          },
          {
            from: "/code-scanning-tools/codeql",
            to: "/integrations/scanners/codeql",
          },
          {
            from: "/code-scanning-tools/contrast",
            to: "/integrations/scanners/contrast",
          },
          {
            from: "/code-scanning-tools/semgrep",
            to: "/integrations/scanners/semgrep",
          },
          {
            from: "/code-scanning-tools/snyk",
            to: "/integrations/scanners/snyk-code",
          },
          {
            from: "/code-scanning-tools/sonar",
            to: "/integrations/scanners/sonarqube",
          },
          {
            from: "/code-scanning-tools/sonarqube",
            to: "/integrations/scanners/sonarqube",
          },

          // Pre-existing /integrations/* aliases → updated to new IA
          { from: "/integrations", to: "/integrations/overview" },
          {
            from: "/integrations/sonar",
            to: "/integrations/scanners/sonarqube",
          },

          // Flat /integrations/<name> URLs from the prior PR → new SCM/scanner subfolders
          {
            from: "/integrations/codeql",
            to: "/integrations/scanners/codeql",
          },
          {
            from: "/integrations/semgrep",
            to: "/integrations/scanners/semgrep",
          },
          {
            from: "/integrations/snyk-code",
            to: "/integrations/scanners/snyk-code",
          },
          {
            from: "/integrations/sonarqube",
            to: "/integrations/scanners/sonarqube",
          },
          {
            from: "/integrations/veracode",
            to: "/integrations/scanners/veracode",
          },
          {
            from: "/integrations/checkmarx",
            to: "/integrations/scanners/checkmarx",
          },
          {
            from: "/integrations/appscan",
            to: "/integrations/scanners/appscan",
          },
          {
            from: "/integrations/contrast",
            to: "/integrations/scanners/contrast",
          },
          {
            from: "/integrations/gitlab-sast",
            to: "/integrations/scanners/gitlab-sast",
          },
          { from: "/integrations/github", to: "/integrations/scms/github" },

          // Removed consolidated wrappers → overview
          {
            from: "/integrations/commercial-scanners",
            to: "/integrations/overview",
          },
          {
            from: "/integrations/oss-aggregator-scanners",
            to: "/integrations/overview",
          },
          {
            from: "/integrations/scm-platforms",
            to: "/integrations/overview",
          },
        ],
      },
    ],
    "docusaurus-plugin-llms",
  ],

  headTags: [
    {
      tagName: "script",
      attributes: { type: "application/ld+json" },
      innerHTML: JSON.stringify({
        "@context": "https://schema.org",
        "@type": "Organization",
        name: "Pixee",
        url: "https://pixee.ai",
        logo: "https://pixee.ai/images/pixee-logo.png",
        sameAs: [
          "https://github.com/pixee",
          "https://www.linkedin.com/company/pixee/",
          "https://twitter.com/pixaboratory",
        ],
        description:
          "Pixee automates security vulnerability triage and remediation at scale.",
      }),
    },
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      navbar: {
        title: "Pixee",
        logo: {
          alt: "Pixee",
          src: "img/pixee-logo.png",
          href: "https://pixee.ai",
        },

        items: [
          {
            position: "left",
            label: "Docs",
            to: "/",
            className: "header-routes",
          },
          {
            type: "html",
            position: "right",
            value:
              '<a href="https://github.com/apps/pixeebot" target="_blank"><div class="header-github-link"></div><a/>',
          },
          {
            type: "html",
            position: "right",
            value:
              '<a href="https://join.slack.com/t/openpixee/shared_invite/zt-1pnk7jqdd-kfwilrfG7Ov4M8rorfOnUA" target="_blank",><div class="header-slack-link"></div><a/>',
          },
        ],
      },
      head: [],
      footer: {
        links: [
          {
            items: [
              {
                html: `
                <div class="footerContent">
                  <div class="copyright"><span>© 2025 Pixee Inc.</span> All rights reserved</div>
                  <div class="socialIcons">
                  <a href="https://twitter.com/pixeebot" target="_blank"><div class="footer-twitter-link"></div></a>
                  <a href="https://www.linkedin.com/company/pixee/" target="_blank"><div class="footer-linkedin-link"></div></a>
                  </div>

                  <div class="links">
                    <a href="https://www.pixee.ai/terms" target="_blank">Terms of Service</a>
                    <a href="https://www.pixee.ai/privacy" target="_blank">Privacy Policy</a>
                    <a href = "mailto: hi@pixee.ai">Contact us</a>
                  </div>
                </div>
                  `,
              },
            ],
          },
        ],
      },
      prism: {
        theme: lightCodeTheme,
        darkTheme: darkCodeTheme,
      },
    }),

  scripts: [
    {
      src: "/js/loadtags.js",
      async: true,
    },
  ],
};

module.exports = config;
