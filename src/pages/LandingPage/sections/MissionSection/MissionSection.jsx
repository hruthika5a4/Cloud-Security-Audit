import React from 'react';
import { CheckCircle2, ShieldAlert, Cpu } from 'lucide-react';
import styles from './MissionSection.module.css';
import Section from '../../../../components/Section/Section';

const MissionSection = () => {
  return (
    <Section 
      id="mission" 
      darker={true}
      className={styles.missionSection}
    >
      <div className={styles.missionContainer}>
        {/* Left: Text */}
        <div className={styles.missionText}>
          <h2 className={styles.title}>
            Building a safer cloud <br />
            <span className={styles.highlightText}>for everyone.</span>
          </h2>
          <p className={styles.description}>
            Our mission is to democratize enterprise-grade cloud security, making it accessible, understandable, and actionable for teams of all sizes without overwhelming complexity.
          </p>
          <ul className={styles.featureList}>
            <li><CheckCircle2 size={20} className={styles.checkIcon} /> <span>AI-driven threat intelligence</span></li>
            <li><CheckCircle2 size={20} className={styles.checkIcon} /> <span>Real-time vulnerability patching</span></li>
            <li><CheckCircle2 size={20} className={styles.checkIcon} /> <span>Zero-trust architecture support</span></li>
          </ul>
        </div>
        
        {/* Right: Glass mockup */}
        <div className={styles.missionVisual}>
          <div className={styles.glassBackdrop}></div>
          
          <div className={styles.mainGlassPanel}>
            <div className={styles.panelHeader}>
              <ShieldAlert size={20} className={styles.alertIcon} />
              <span>Vulnerability Detected</span>
            </div>
            <div className={styles.panelBody}>
              <div className={styles.codeBlock}>
                <code>
                  <span className={styles.codeKey}>"issue"</span>: <span className={styles.codeString}>"Public S3 Bucket"</span>,<br/>
                  <span className={styles.codeKey}>"severity"</span>: <span className={styles.codeString}>"HIGH"</span>,<br/>
                  <span className={styles.codeKey}>"resource"</span>: <span className={styles.codeNumber}>"arn:aws:s3:::prod-db"</span>
                </code>
              </div>
            </div>
          </div>
          
          <div className={styles.subGlassPanel}>
            <Cpu size={20} className={styles.iconBlue} />
            <div className={styles.subText}>
              <span className={styles.subTitle}>Recommendation Provided</span>
              <span className={styles.subStatus}>Enable BlockPublicAccess via IAM</span>
            </div>
          </div>
          
          <div className={styles.reportGlassPanel}>
            <CheckCircle2 size={20} className={styles.iconGreen} />
            <div className={styles.subText}>
              <span className={styles.subTitle}>Download Report</span>
              <span className={styles.subStatus}>PDF Export Ready</span>
            </div>
          </div>
        </div>
      </div>
    </Section>
  );
};

export default MissionSection;
