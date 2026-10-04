import React, { useContext, useState, useEffect } from 'react';
import LandingPage from './pages/LandingPage/LandingPage';
import DashboardPage from './pages/Dashboard/DashboardPage';
import ProjectsPage from './pages/Dashboard/ProjectsPage';
import ProjectDetailsPage from './pages/Dashboard/ProjectDetailsPage';
import ScanHistoryPage from './pages/Dashboard/ScanHistoryPage';
import SettingsPage from './pages/Dashboard/SettingsPage';
import AutomationPage from './pages/Dashboard/AutomationPage';

// Auth Pages
import LoginPage from './pages/Auth/LoginPage/LoginPage';
import RegisterPage from './pages/Auth/RegisterPage/RegisterPage';
import ForgotPasswordPage from './pages/Auth/ForgotPasswordPage/ForgotPasswordPage';
import ResetPasswordPage from './pages/Auth/ResetPasswordPage/ResetPasswordPage';
import OTPVerifyPage from './pages/Auth/OTPVerifyPage/OTPVerifyPage';

import './App.css';

import { AuthContext } from './contexts/AuthContext';
import DashboardLayout from './pages/Dashboard/DashboardLayout';

// Redirects unauthenticated users → /login
const ProtectedRoute = ({ children }) => {
  const { user, loading } = useContext(AuthContext);
  if (loading) return null;
  if (!user) { window.location.replace('/login'); return null; }
  return children;
};

// Redirects already-logged-in users → /dashboard (for /login, /register)
const GuestRoute = ({ children }) => {
  const { user, loading } = useContext(AuthContext);
  if (loading) return null;
  if (user) { window.location.replace('/dashboard'); return null; }
  return children;
};

const DashboardRouter = ({ path }) => {
  let content = null;
  if (path === '/dashboard/projects') content = <ProjectsPage />;
  else if (path.startsWith('/dashboard/projects/') && path.split('/').length === 4) content = <ProjectDetailsPage projectId={path.split('/')[3]} />;
  else if (path === '/dashboard/history') content = <ScanHistoryPage />;
  else if (path === '/dashboard/settings') return <SettingsPage />; // Full page, no sidebar
  else if (path === '/dashboard/automation') content = <AutomationPage />;
  else content = <DashboardPage />;

  return (
    <DashboardLayout currentPath={path}>
      {content}
    </DashboardLayout>
  );
};

// Simple Error Boundary Component
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, errorInfo) {
    console.error("APP CRASH:", error, errorInfo);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: '40px', textAlign: 'center', backgroundColor: '#fff', height: '100vh', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <h1 style={{ color: '#ef4444' }}>Something went wrong.</h1>
          <p style={{ color: '#64748b' }}>{this.state.error?.message || "Unknown Error"}</p>
          <button onClick={() => window.location.replace('/')} style={{ marginTop: '20px', padding: '10px 20px', backgroundColor: '#2563eb', color: '#fff', border: 'none', borderRadius: '8px', cursor: 'pointer' }}>
            Back to Home
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

function App() {
  const [currentPath, setCurrentPath] = useState(window.location.pathname);

  useEffect(() => {
    const handlePopState = () => {
      console.log("Popstate detected:", window.location.pathname);
      setCurrentPath(window.location.pathname);
    };
    window.addEventListener('popstate', handlePopState);

    const handleClick = (e) => {
      const a = e.target.closest('a');
      if (a && a.href && a.origin === window.location.origin && a.target !== '_blank' && !a.hasAttribute('download')) {
        const isDashboard = a.pathname.startsWith('/dashboard');
        // Prevent default and use HTML5 history API for internal links
        e.preventDefault();
        window.history.pushState(null, '', a.pathname);
        setCurrentPath(a.pathname);
      }
    };
    document.addEventListener('click', handleClick);

    return () => {
      window.removeEventListener('popstate', handlePopState);
      document.removeEventListener('click', handleClick);
    };
  }, []);

  const path = currentPath;

  let renderContent = null;
  if (path.startsWith('/dashboard')) {
    renderContent = <ProtectedRoute><DashboardRouter path={path} /></ProtectedRoute>;
  } else if (path === '/login') {
    renderContent = <GuestRoute><LoginPage /></GuestRoute>;
  } else if (path === '/register') {
    renderContent = <GuestRoute><RegisterPage /></GuestRoute>;
  } else if (path === '/forgot-password') {
    renderContent = <ForgotPasswordPage />;
  } else if (path === '/reset-password') {
    renderContent = <ResetPasswordPage />;
  } else if (path === '/verify-otp') {
    renderContent = <OTPVerifyPage />;
  } else {
    renderContent = (
      <div className="app">
        <LandingPage />
      </div>
    );
  }

  return (
    <ErrorBoundary>
      {renderContent}
    </ErrorBoundary>
  );
}

export default App;
