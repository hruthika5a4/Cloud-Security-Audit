import React from 'react';
import Header from '../../components/Layout/Header/Header';
import Footer from '../../components/Layout/Footer/Footer';
import HeroSection from './sections/HeroSection/HeroSection';
import FeaturesSection from './sections/FeaturesSection/FeaturesSection';
import MissionSection from './sections/MissionSection/MissionSection';
import WorkflowSection from './sections/WorkflowSection/WorkflowSection';
import CTASection from './sections/CTASection/CTASection';

const LandingPage = () => {
  return (
    <div className="landing-page-wrapper">
      <Header />
      <main>
        <HeroSection />
        <FeaturesSection />
        <MissionSection />
        <WorkflowSection />
        <CTASection />
      </main>
      <Footer />
    </div>
  );
};

export default LandingPage;
