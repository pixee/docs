// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const lightCodeTheme = require('prism-react-renderer/themes/github');
const darkCodeTheme = require('prism-react-renderer/themes/dracula');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Pixee',
  tagline: 'Elevate your code, one automated commit at a time.', //TODO: We need a tag line!
  url: 'https://docs.pixee.ai/',
  baseUrl: '/',
  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',
  favicon: 'img/favicon.ico',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'pixee', // Usually your GitHub org/user name.
  projectName: 'internal-docs', // Usually your repo name.
  deploymentBranch: 'main',

  // Even if you don't use internalization, you can use this field to set useful
  // metadata like html lang. For example, if your site is Chinese, you may want
  // to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  stylesheets: [
    'https://fonts.googleapis.com/css?family=Source+Sans+Pro:200,200i,300,300i,400,400i,600,600i,700,700i,900,900i&display=swap',
  ],

  presets: [
    [
      '@docusaurus/preset-classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          routeBasePath: '/',
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl: 'https://github.com/pixee/docs/edit/main/',
        },
        blog: {
          showReadingTime: true,
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl: 'https://github.com/pixee/docs/edit/main/',
        },
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
        gtag: {
          trackingID: 'G-1M7HM648QD',
          anonymizeIP: true,
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      navbar: {
        title: 'Pixee',
        logo: {
          alt: 'Pixee',
          src: 'img/logo.png',
          href: 'https://pixee.ai',
        },

        items: [
          {
            type: 'doc',
            docId: 'intro',
            position: 'left',
            label: 'Docs',
          },
          { to: '/status', label: 'Status', position: 'left' },
          {
            type: 'html',
            position: 'right',
            value:
              '<a href="https://github.com/apps/pixeebot" target="_blank"><img src="img/github-logo.png" width="25px" style="padding-Top:5px"/><a/>',
          },
          {
            type: 'html',
            position: 'right',
            value:
              '<a href="https://join.slack.com/t/openpixee/shared_invite/zt-1pnk7jqdd-kfwilrfG7Ov4M8rorfOnUA" target="_blank",><img src="img/slack-logo.png" width="20px" style="padding-Top:5px"/><a/>',
          },
        ],
      },
      head: [],
      // footer: {
      //   style: 'dark',
      //   // copyright: `Copyright © ${new Date().getFullYear()} My Project, Inc. Built with Docusaurus.`,
      //   links: [
      //     {
      //       title:
      //         'Copyright © ${new Date().getFullYear()} My Project, Inc. Built with Docusaurus.',
      //     },
      //     {
      //       items: [
      //         {
      //           label: 'Terms of Service',
      //           href: 'https://www.pixee.ai/terms',
      //         },
      //       ],
      //     },
      //     {
      //       items: [
      //         {
      //           label: 'Privacy Policy',
      //           href: 'https://www.pixee.ai/privacy',
      //         },
      //       ],
      //     },
      //     {
      //       items: [
      //         {
      //           label: 'Contact us',
      //           href: 'https://pixee.trustcenter.sprinto.com/',
      //         },
      //       ],
      //     },
      //   ],
      //   // customFooter: require.resolve('./src/theme/Footer.js'),
      //   // copyright: `Copyright © 2023 Pixee Inc.`,
      // },
      footer: {
        links: [
          {
            items: [
              {
                html: `
                <div class="footerContent">
                  <div class="copyright"><span>© 2023 Pixee Inc.</span> All rights reserved</div>
                  <div class="socialIcons">
                  <a href="https://twitter.com/pixeebot" target="_blank"><img src="img/twitter-logo.svg" width="16px"></a>
                  <a href="https://www.linkedin.com/company/pixee/" target="_blank"><img src="img/linkedin-logo.svg" width="16px"></a>
                  </div>
                  <div class="links">
                    <a href="https://www.pixee.ai/terms" target="_blank">Terms of Service</a>
                    <a href="https://www.pixee.ai/privacy" target="_blank">Privacy Policy</a>
                    <a href="#">Contact us</a>
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
      src: '/js/loadtags.js',
      async: true,
    },
  ],
};

module.exports = config;
