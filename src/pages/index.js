import React from 'react';
import Layout from '@theme/Layout';
import HomepageFeatures from '@site/src/components/HomepageFeatures';

import styles from './index.module.css';

function HomepageHeader() {
  return (
    <div className={styles.heroBanner}>
      <h1>PixeeDocs 🧚🤖</h1>
      <p>
        Everything you need to know about Pixeebot,
        <br /> your automated product security engineer.
      </p>
    </div>
  );
}

export default function Home() {
  return (
    <Layout>
      <HomepageHeader />
      <main>
        <HomepageFeatures />
      </main>
    </Layout>
  );
}
