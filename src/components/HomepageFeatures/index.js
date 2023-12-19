import React from 'react';
import styles from './styles.module.css';
import Link from '@docusaurus/Link';

export default function HomepageFeatures() {
  const navigateToDocs = (type) => {
    if (type === 1) {
      window.location = '/installing';
    } else if (type === 2) {
      window.location = '/codemods/overview';
    } else if (type === 3) {
      window.location = 'https://github.com/pixee/pixee-cli';
    } else if (type === 4) {
      window.location = '/configuring';
    } else if (type === 5) {
      window.location = '/running-your-own';
    } else if (type === 6) {
      window.location = '/faqs';
    } else if (type === 7) {
      window.location = '/using-pixeebot';
    } else {
      window.location = '/release-notes';
    }
  };
  return (
    <>
      <div className={styles.grid}>
        <div className={styles.item}>
          <h1 onClick={() => navigateToDocs(1)}>
            ⬇ <span>Install Pixeebot</span>
          </h1>
          <p>
            Pixeebot installation begins by visiting our{' '}
            <Link to="https://github.com/apps/pixeebot">GitHub App page</Link>.
            From there, click the <span>Configure</span> button and follow the
            prompts from GitHub. You’ll be directed to your Pixee dashboard once
            the process is complete.
          </p>
        </div>
        <div className={styles.item}>
          <h1 onClick={() => navigateToDocs(2)}>
            🌱 <span>Core codemods</span>
          </h1>
          <p>
            Get detailed information on our core codemods, maintained as part of
            the <Link to="https://codemodder.io/">codemodder project</Link> to
            help strengthen your code.
          </p>
          <p>
            <Link to="/category/java">Java</Link>
          </p>
          <p>
            <Link to="/category/python">Python</Link>
          </p>
        </div>
        <div className={styles.item} onClick={() => navigateToDocs(3)}>
          <h1>
            💻 <span>Pixee CLI</span>
          </h1>
          <p>
            Try out the power of Pixee codemods locally with our command line interface. See how
            Pixee can improve and harden your code before installing the GitHub app.
          </p>
        </div>
        <div className={styles.item} onClick={() => navigateToDocs(4)}>
          <h1>
            ⚙️ <span>Configuration</span>
          </h1>
          <p>
            Understand how and where to configure Pixeebot, view examples and
            get details about specific properties.
          </p>
        </div>
        <div className={styles.item} onClick={() => navigateToDocs(5)}>
          <h1>
            ✨️️ <span>Custom codemods</span>
          </h1>
          <p>Coming soon!</p>
        </div>
        <div className={styles.item} onClick={() => navigateToDocs(6)}>
          <h1>
            ❓ <span>FAQs</span>
          </h1>
          <p>
            Addressing common topics such as data handling and use of LLMs.
          </p>
        </div>
        <div className={styles.item} onClick={() => navigateToDocs(7)}>
          <h1>
            👤️️ <span>User guide</span>
          </h1>
          <p>
            Learn more about how to engage with Pixeebot, including a summon
            command to call it whenever you’re ready!
          </p>
        </div>
        <div className={styles.item} onClick={() => navigateToDocs(7)}>
          <h1>
            📄 <span>Release notes</span>
          </h1>
          <p>
            <br /> We are constantly updating our product. Check out our weekly release notes here.
          </p>
        </div>
      </div>
    </>
  );
}
