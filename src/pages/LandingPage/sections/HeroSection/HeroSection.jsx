import React, { useState, useEffect } from 'react';
import { ArrowRight, ShieldCheck, Activity, SearchCode, CheckCircle2 } from 'lucide-react';
import styles from './HeroSection.module.css';
import Button from '../../../../components/Button/Button';

const isLoggedIn = () => {
  try {
    const token     = localStorage.getItem('auditscope_token');
    if (!token) return false;
    const parts = token.split('.');
    if (parts.length < 2) return false;
    const payload   = JSON.parse(atob(parts[1]));
    const loginTime = parseInt(localStorage.getItem('auditscope_login_time') || '0', 10);
    if (loginTime && Date.now() - loginTime > 6 * 60 * 60 * 1000) return false;
    if (!payload || !payload.exp) return false;
    return payload.exp * 1000 > Date.now();
  } catch (e) { return false; }
};

const HeroSection = () => {
  const [loggedIn, setLoggedIn] = useState(false);

  useEffect(() => {
    setLoggedIn(isLoggedIn());
  }, []);

  const handleCTA = () => {
    window.location.href = loggedIn ? '/dashboard' : '/register';
  };

  return (
    <section className={styles.hero}>
      <div className={styles.meshBackground}>
        <div className={styles.blob1}></div>
        <div className={styles.blob2}></div>
        <div className={styles.blob3}></div>
        <div className={styles.glassOverlay}></div>
      </div>
      
      <div className={`container ${styles.container}`}>
        <div className={styles.heroGrid}>
          {/* Left Text Content */}
          <div className={styles.content}>
            <div className={styles.badge}>
              <span className={styles.badgePulse}></span>
              Enterprise Security
            </div>
            <h1 className={styles.title}>
              Secure your <span className={styles.textHighlight}>Cloud</span> infrastructure with ease.
            </h1>
            <p className={styles.subtitle}>
              The modern security audit accelerator. We detect vulnerabilities instantly so you can focus on building your next big thing.
            </p>
            <div className={styles.ctaGroup}>
              <Button variant="primary" size="large" onClick={handleCTA}>
                {loggedIn ? 'Go to Dashboard' : 'Free Scan'} <ArrowRight size={18} style={{ marginLeft: '8px' }} />
              </Button>
              {!loggedIn && (
                <div className={styles.trustSnippet}>
                  <CheckCircle2 size={16} className={styles.checkIcon} />
                  <span>No credit card required</span>
                </div>
              )}
            </div>
          </div>

          {/* Right Visual Floating Widgets */}
          <div className={styles.visuals}>
            <div className={`${styles.glassWidget} ${styles.widgetScore}`}>
              <div className={styles.widgetHeader}>
                <ShieldCheck size={20} className={styles.iconPrimary} />
                <span>Health Score</span>
              </div>
              <div className={styles.scoreCircle}>98%</div>
              <p className={styles.scoreText}>All systems secure</p>
            </div>
            
            <div className={`${styles.glassWidget} ${styles.widgetActivity}`}>
              <div className={styles.widgetHeader}>
                <Activity size={20} className={styles.iconViolet} />
                <span>Live Scan</span>
              </div>
              <div className={styles.activityBars}>
                <div className={styles.bar} style={{ height: '40%' }}></div>
                <div className={styles.bar} style={{ height: '80%' }}></div>
                <div className={styles.bar} style={{ height: '60%' }}></div>
                <div className={styles.bar} style={{ height: '100%', backgroundColor: '#10b981' }}></div>
              </div>
            </div>

            <div className={`${styles.glassWidget} ${styles.widgetScanner}`}>
              <div className={styles.widgetHeader}>
                <SearchCode size={20} className={styles.iconCyan} />
                <span>Live Intelligence Scan</span>
              </div>
              <div className={styles.scannerBox}>
                <div className={styles.scanLine}></div>
                <div className={styles.codeLine}><span className={styles.codeTime}>[0ms]</span> Fetching IAM policies...</div>
                <div className={styles.codeLine}><span className={styles.codeTime}>[12ms]</span> Inspecting root roles...</div>
                <div className={styles.codeLineActive}><span className={styles.codeTime}>[45ms]</span> Evaluating permissions...</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default HeroSection;
