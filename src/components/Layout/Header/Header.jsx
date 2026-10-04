import React, { useState, useEffect } from 'react';
import styles from './Header.module.css';
import Button from '../../Button/Button';

// Read auth state directly from localStorage (no React context needed here)
const isLoggedIn = () => {
  try {
    const token = localStorage.getItem('auditscope_token');
    if (!token) return false;
    const parts = token.split('.');
    if (parts.length < 2) return false;
    const payload = JSON.parse(atob(parts[1]));
    // Also enforce the 6-hour session limit (loginTime stored separately)
    const loginTime = parseInt(localStorage.getItem('auditscope_login_time') || '0', 10);
    const sixHours  = 6 * 60 * 60 * 1000;
    if (loginTime && Date.now() - loginTime > sixHours) return false;
    if (!payload || !payload.exp) return false;
    return payload.exp * 1000 > Date.now();
  } catch (e) {
    return false;
  }
};

const Header = () => {
  const [loggedIn, setLoggedIn] = useState(false);

  useEffect(() => {
    setLoggedIn(isLoggedIn());
    // Re-check when storage changes (e.g. login/logout in another tab)
    const handler = () => setLoggedIn(isLoggedIn());
    window.addEventListener('storage', handler);
    return () => window.removeEventListener('storage', handler);
  }, []);

  const goDashboard = () => { window.location.href = '/dashboard'; };
  const goLogin     = () => { window.location.href = '/login'; };
  const goRegister  = () => { window.location.href = '/register'; };

  return (
    <header className={styles.header}>
      <div className={`container ${styles.headerContent}`}>
        <div className={styles.logo}>
          <a href="/">
            <div className={styles.logoIcon}>A</div>
            <div className={styles.logoText}>
              <span className={styles.logoMain}>Audit</span>
              <span className={styles.logoSub}>Scope</span>
            </div>
          </a>
        </div>

        <nav className={styles.nav}>
          <ul className={styles.navList}>
            <li><a href="#features"    className={styles.navLink}>Features</a></li>
            <li><a href="#about-us"    className={styles.navLink}>About Us</a></li>
            <li><a href="#how-it-works" className={styles.navLink}>How it Works</a></li>
            <li><a href="#pricing"     className={styles.navLink}>Pricing</a></li>
          </ul>
        </nav>

        <div className={styles.actions}>
          {loggedIn ? (
            /* ── Already logged in ── */
            <Button variant="primary" onClick={goDashboard}>
              Go to Dashboard →
            </Button>
          ) : (
            /* ── Not logged in ── */
            <>
              <a href="/login" className={styles.loginBtn} style={{ textDecoration: 'none' }}>
                <Button variant="ghost" as="span">Log In</Button>
              </a>
              <Button variant="primary" onClick={goRegister}>Free Scan</Button>
            </>
          )}
        </div>
      </div>
    </header>
  );
};

export default Header;
