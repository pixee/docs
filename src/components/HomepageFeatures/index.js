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
            Welcome to Pixeebot! Learn how Pixeebot can: <ul>
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
            Learn about the code scanning tools Pixeebot supports and how to
            give Pixeebot access to your tool findings.
          </p>
        </div>
        <div className={styles.item} onClick={() => navigateToDocs(3)}>
           <h1>
            ⬇ <span>Get Started</span>
           </h1>
           <p>
             Pixeebot is available as a{" "}
             <Link to="https://github.com/apps/pixeebot">GitHub App</Link>.
             Install it for free to try it out, or <Link to="https://www.pixee.ai/demo-landing-page">contact us</Link> for a demo and on-prem support.
           </p>
        </div>
        <div className={styles.item} onClick={() => navigateToDocs(6)}>
          <h1>
            ❓ <span>FAQs</span>
          </h1>
          <p>Addressing common topics such as data handling and use of LLMs.</p>
        </div>
      </div>
    </>
  );
}
