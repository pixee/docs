import React from 'react';
import styles from './styles.module.css';

export default function HomepageFeatures() {
  return (
    <>
      <div className={styles.grid}>
        <div className={styles.item}>
          <h1>
            ⬇ <span>Install Pixeebot</span>
          </h1>
          <p>
            Pixeebot installation begins by visiting our Github App page. From
            there, click the Configure button and follow the prompts from
            GitHub. You’ll be directed to your Pixee dashboard once the process
            is complete.
          </p>
        </div>
        <div className={styles.item}>
          <h1>
            🌱 <span>Core codemods</span>
          </h1>
          <p>
            Get detailed information on our core codemods, maintained as part of
            the codemodder project to help strengthen your code.
          </p>
          <p>Java</p>
          <p>Python</p>
        </div>
        <div className={styles.item}>
          <h1>
            ⚙️ <span>Configuration</span>
          </h1>
          <p>
            Understand how and where to configure Pixeebot, view examples and
            get details about specific fields.
          </p>
        </div>
        <div className={styles.item}>
          <h1>
            ✨️️ <span>Custom codemods</span>
          </h1>
          <p>Coming soon!</p>
        </div>
        <div className={styles.item}>
          <h1>
            ❓ <span>AQs</span>
          </h1>
          <p>
            Understand how and where to configure Pixeebot, view examples and
            get details about specific fields.
          </p>
        </div>
        <div className={styles.item}>
          <h1>
            👤️️ <span>User guide</span>
          </h1>
          <p>
            Learn more about how to engage with Pixeebot, including a summon
            command to call it whenever you’re ready!
          </p>
        </div>
      </div>
      <div className={styles.lastGrid}>
        <div className={styles.item}>
          <h1>
            📄 <span>Release notes</span>
          </h1>
          <p>
            May 15, 2023 <br /> This release supports Java code on Github.
          </p>
        </div>
      </div>
    </>
  );
}
