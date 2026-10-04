import React from 'react';
import { KeyRound, ScanSearch, Wand2 } from 'lucide-react';
import styles from './WorkflowSection.module.css';
import Section from '../../../../components/Section/Section';

const steps = [
  {
    icon: <KeyRound size={28} />,
    title: 'Connect Your Cloud',
    description: 'Securely link your AWS, Azure, or Google Cloud accounts in just a few clicks. No complex configurations.'
  },
  {
    icon: <ScanSearch size={28} />,
    title: 'Automated Deep Scan',
    description: 'Our proprietary engine scans over 200 security points across your infrastructure, identifying misconfigurations and vulnerabilities.'
  },
  {
    icon: <Wand2 size={28} />,
    title: 'Instant Recommendations',
    description: 'Receive a prioritized list of actionable steps to secure your environment, reducing resolution time from days to minutes.'
  }
];

const WorkflowSection = () => {
  return (
    <Section 
      id="how-it-works"
      title={<span>A beautifully simple <br /> <span className={styles.highlightTitle}>three-step workflow.</span></span>}
      subtitle="Security doesn't have to be complicated. Get started and secure in minutes."
      darker={false}
      className={styles.workflowSection}
    >
      <div className={styles.timelineContainer}>
        {/* The central vertical line */}
        <div className={styles.timelineLine}></div>
        
        {steps.map((step, index) => (
          <div key={index} className={`${styles.timelineItem} ${index % 2 === 0 ? styles.itemLeft : styles.itemRight}`}>
            {/* The dot on the timeline */}
            <div className={styles.timelineDot}>
               <div className={styles.dotInner}></div>
            </div>
            
            <div className={styles.timelineCard}>
              <div className={styles.iconWrapper}>
                {step.icon}
              </div>
              <div className={styles.cardContent}>
                <span className={styles.stepLabel}>Step 0{index + 1}</span>
                <h3 className={styles.stepTitle}>{step.title}</h3>
                <p className={styles.stepDescription}>{step.description}</p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </Section>
  );
};

export default WorkflowSection;
