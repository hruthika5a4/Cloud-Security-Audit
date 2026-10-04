import React from 'react';
import styles from './AuthLayout.module.css';

const AuthLayout = ({ children, title, subtitle }) => {
  return (
    <div className={styles.layout}>
      {/* Background aesthetics */}
      <div className={styles.backgroundGlowTop}></div>
      <div className={styles.backgroundGlowBottom}></div>

      <div className={styles.container}>
        <div className={styles.logoRow}>
          <a href="/" className={styles.logo}>
            <span className={styles.logoIcon}></span>
            {/* <span className="text-gradient">Security Audit</span> */}
          </a>
        </div>

        <div className={styles.card}>
          <div className={styles.cardHeader}>
            <h1 className={styles.title}>{title}</h1>
            {subtitle && <p className={styles.subtitle}>{subtitle}</p>}
          </div>
          <div className={styles.cardBody}>
            {children}
          </div>
        </div>
      </div>
    </div>
  );
};

export default AuthLayout;
