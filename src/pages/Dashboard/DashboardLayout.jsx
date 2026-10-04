import React from 'react';
import Sidebar from './components/Sidebar/Sidebar';
import DashboardNavbar from './components/DashboardNavbar/DashboardNavbar';
import OnboardingTour from '../../components/OnboardingTour/OnboardingTour';
import styles from './DashboardLayout.module.css';

const DashboardLayout = ({ children, currentPath }) => {
  return (
    <div className={styles.dashboardContainer}>
      <Sidebar currentPath={currentPath} />
      <div className={styles.mainContentArea}>
        <DashboardNavbar />
        <main className={styles.pageContent}>
          {children}
        </main>
      </div>
      {/* Onboarding tour — only renders for new users (auto-dismissed after completion) */}
      <OnboardingTour />
    </div>
  );
};

export default DashboardLayout;
