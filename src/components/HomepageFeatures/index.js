import React from "react";
import styles from "./styles.module.css";
import Link from "@docusaurus/Link";

export default function HomepageFeatures() {
  const navigateToDocs = (type) => {
    if (type === 1) {
      window.location = "/intro";
    } else if (type === 2) {
      window.location = "/code-scanning-tools/overview";
    } else if (type === 3) {
      window.location = "/installing";
    } else if (type === 4) {
      window.location = "/configuring";
    } else if (type === 5) {
      window.location = "/running-your-own";
    } else if (type === 6) {
      window.location = "/faqs";
    } else if (type === 7) {
      window.location = "/using-pixeebot";
    } else {
      window.location = "/release-notes";
    }
  };
  return (
    <>
      <div className={styles.grid}>
        <div className={styles.item} onClick={() => navigateToDocs(1)}>
          <h1>
            👋 <span>Introduction</span>
          </h1>
          <p>
            Welcome to Pixee! Learn how Pixee can:{" "}
            <ul>
              <li>Fix security issues reported by your tools</li>
              <li>Triage security tool findings</li>
              <li>Harden your code</li>
            </ul>
          </p>
        </div>
        <div className={styles.item} onClick={() => navigateToDocs(2)}>
          <h1>
            🛠️ <span>Supported Tools</span>
          </h1>
          <p>
            Learn about the code scanning tools Pixee supports and how to give
            Pixee access to your tool findings.
          </p>
        </div>
        <div className={styles.item} onClick={() => navigateToDocs(3)}>
          <h1>
            ⬇ <span>Get Started</span>
          </h1>
          <p>
            Reach out to us to{" "}
            <Link to="https://www.pixee.ai/demo-landing-page">learn more,</Link>{" "}
            see a demo, and get a free trial.
          </p>
        </div>
        <div className={styles.item} onClick={() => navigateToDocs(6)}>
          <h1>
            ❓ <span>FAQs</span>
          </h1>
          <p>
            Addressing common topics such as data handling, our use of AI, on
            premise offering, etc.
          </p>
        </div>
      </div>
      <br />
      <br />
    </>
  );
}
