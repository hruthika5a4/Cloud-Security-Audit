import React from 'react';
import { ArrowRight, Sparkles } from 'lucide-react';
import styles from './CTASection.module.css';
import Section from '../../../../components/Section/Section';
import Button from '../../../../components/Button/Button';

const CTASection = () => {
  return (
    <Section 
      id="pricing"
      className={styles.ctaSection}
    >
      <div className={styles.islandContainer}>
        <div className={styles.ambientGlowTop}></div>
        <div className={styles.ambientGlowBottom}></div>
        
        <div className={styles.islandContent}>
          <div className={styles.sparkleBadge}>
             <Sparkles size={16} className={styles.sparkleIcon} />
             Get Started
          </div>
          <h2 className={styles.title}>Secure your cloud today.</h2>
          <p className={styles.description}>
            Join thousands of teams shipping faster with automated security intelligence.
          </p>
          <div className={styles.actions}>
            <Button className={styles.primaryIslandBtn} size="large" onClick={() => window.location.href = '/register'}>
              Free Scan <ArrowRight size={18} style={{ marginLeft: '8px' }} />
            </Button>
            <Button className={styles.secondaryIslandBtn} size="large">Talk to Sales</Button>
          </div>
        </div>
      </div>
    </Section>
  );
};

export default CTASection;
