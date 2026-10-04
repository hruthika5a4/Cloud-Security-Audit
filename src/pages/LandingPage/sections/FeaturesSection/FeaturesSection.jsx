import React from 'react';
import { Users, FolderLock, Network, Shield } from 'lucide-react';
import styles from './FeaturesSection.module.css';
import Section from '../../../../components/Section/Section';

const FeaturesSection = () => {
  return (
    <Section 
      id="features"
      title={<span>Security disguised as <br /> <span className={styles.highlightTitle}>pure simplicity.</span></span>}
      subtitle="Complete visibility across your hybrid environment. We process the complex security audits, you just get the insights."
      darker={true}
      className={styles.featuresSection}
    >
      <div className={styles.bentoGrid}>
        
        {/* Large Feature 1 */}
        <div className={`${styles.bentoCard} ${styles.cardLarge}`}>
          <div className={styles.cardContent}>
            <div className={styles.iconWrapperLarge}>
              <Users size={48} className={styles.iconBlue} />
            </div>
            <h3 className={styles.cardTitle}>Control Who Has Access</h3>
            <p className={styles.cardDescription}>
              See exactly who can use your cloud accounts. We automatically scan all IAM roles, identify over-privileged users, and provide one-click removal strategies to keep your data safe and private from insider threats.
            </p>
          </div>
          {/* Abstract visual for the large card */}
          <div className={styles.cardGraphic}>
            <div className={styles.graphicCircle}>
              <Shield size={64} className={styles.graphicIcon} />
            </div>
          </div>
        </div>

        {/* Small Feature 2 */}
        <div className={`${styles.bentoCard} ${styles.cardSmall}`}>
          <div className={styles.cardContent}>
            <div className={styles.iconWrapperSmall}>
              <FolderLock size={28} className={styles.iconViolet} />
            </div>
            <h3 className={styles.cardTitleSmall}>Protect Your Files</h3>
            <p className={styles.cardDescriptionSmall}>
              We check all your storage folders (S3, Blob, etc). If files are completely open, we help you lock them down quickly.
            </p>
          </div>
        </div>

        {/* Small Feature 3 */}
        <div className={`${styles.bentoCard} ${styles.cardSmall}`}>
          <div className={styles.cardContent}>
            <div className={styles.iconWrapperSmall}>
              <Network size={28} className={styles.iconCyan} />
            </div>
            <h3 className={styles.cardTitleSmall}>Secure Your Network</h3>
            <p className={styles.cardDescriptionSmall}>
              We scan your firewalls and network settings, finding any "open doors" that could let attackers into your servers.
            </p>
          </div>
        </div>

      </div>
    </Section>
  );
};

export default FeaturesSection;
