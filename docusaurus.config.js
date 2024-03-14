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
      }),
    ],
  ],

  plugins: [
    [
      "@docusaurus/plugin-client-redirects",
      {
        redirects: [
          {
            to: "/code-scanning-tools/overview",
            from: "/integrations",
          },
          {
            to: "/code-scanning-tools/sonar",
            from: "/integrations/sonar",
          },
          {
            to: "/code-scanning-tools/codeql",
            from: "/integrations/codeql",
          },
          {
            to: "/code-scanning-tools/semgrep",
            from: "/integrations/semgrep",
          },

          // You can add more redirects here as needed
        ],
      },
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      announcementBar: {
        id: "CLI_launch",
        content:
          '<b>🎉 Introducing the Pixee CLI.</b> Bring the power of Pixee\'s <a target="_blank" href="https://codemodder.io/">Codemodder framework</a> to your local development environment. <a target="_blank" href="https://github.com/pixee/pixee-cli">Learn more</a>',
        backgroundColor: "fbfafb",
        textColor: "1c1533",
        isCloseable: true,
      },
      navbar: {
        title: "Pixee",
        logo: {
          alt: "Pixee",
          src: "img/pixee-logo.png",
          href: "https://pixee.ai",
        },

        items: [
          {
            type: "doc",
            docId: "intro",
            position: "left",
            label: "Docs",
            className: "header-routes",
          },
          {
            to: "/status",
            label: "Status",
            position: "left",
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
                  <div class="copyright"><span>© 2023 Pixee Inc.</span> All rights reserved</div>
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
