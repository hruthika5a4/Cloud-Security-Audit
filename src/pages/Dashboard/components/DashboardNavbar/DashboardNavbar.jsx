import React, { useState, useEffect, useContext, useRef } from 'react';
import styles from './DashboardNavbar.module.css';
import Select from '../../../../components/Select/Select';
import Button from '../../../../components/Button/Button';
import ScannerModal from '../../../../components/ScannerModal/ScannerModal';
import { AuthContext } from '../../../../contexts/AuthContext';

const getServiceName = (resource, id = '') => {
  if (id) {
    const parts = id.split('-');
    const prefix = (parts[1] || '').toUpperCase();
    if (prefix === 'IAM') return 'IAM';
    if (prefix === 'VM' || prefix === 'COMPUTE' || prefix === 'EC2') return 'Compute';
    if (prefix === 'STORAGE' || prefix === 'S3') return 'Storage';
    if (prefix === 'SQL' || prefix === 'RDS') return 'Database';
    if (prefix === 'NET' || prefix === 'FW' || prefix === 'FIREWALL') return 'Networking';
    if (prefix === 'GKE' || prefix === 'EKS') return 'Kubernetes';
    if (prefix === 'LB' || prefix === 'ELB') return 'Load Balancers';
    if (prefix === 'CLOUDRUN' || prefix === 'FUNCTION' || prefix === 'SERVERLESS' || prefix === 'LAMBDA') return 'Serverless';
    if (prefix === 'BQ' || prefix === 'BIGQUERY') return 'BigQuery';
    if (prefix === 'KMS') return 'KMS';
    if (prefix === 'LOG' || prefix === 'OBS' || prefix === 'MONITOR') {
      if (id.toUpperCase().includes('TRANSPARENCY')) return 'Access Transparency';
      return 'Logging & Monitoring';
    }
    if (prefix === 'DATAPROC') return 'Dataproc';
    if (prefix === 'DNS') return 'Cloud DNS';
    if (prefix === 'APIKEY') return 'API Keys';
    if (prefix === 'ESSENTIAL') return 'Essential Contacts';
  }

  const match = (resource || '').match(/^([^(]+)/);
  let sName = match ? match[1].trim() : 'Other';
  const lowerName = sName.toLowerCase();
  
  if (lowerName.includes('compute') || lowerName.includes('vm') || lowerName.includes('instance')) return 'Compute';
  if (lowerName.includes('iam') || lowerName.includes('service account')) return 'IAM';
  if (lowerName.includes('storage') || lowerName.includes('bucket')) return 'Storage';
  if (lowerName.includes('sql') || lowerName.includes('database') || lowerName.includes('rds')) return 'Database';
  if (lowerName.includes('network') || lowerName.includes('vpc') || lowerName.includes('firewall') || lowerName.includes('subnet')) return 'Networking';
  if (lowerName.includes('dns')) return 'Cloud DNS';
  if (lowerName.includes('kubernetes') || lowerName.includes('gke') || lowerName.includes('eks')) return 'Kubernetes';
  if (lowerName.includes('kms') || lowerName.includes('key')) return 'KMS';
  if (lowerName.includes('func') || lowerName.includes('lambda') || lowerName.includes('serverless') || lowerName.includes('cloudrun')) return 'Serverless';
  if (lowerName.includes('load balancer') || lowerName.includes('backend service') || lowerName.includes('lb')) return 'Load Balancers';
  if (lowerName.includes('bigquery') || lowerName.includes('bq') || lowerName.includes('dataset') || lowerName.includes('table')) return 'BigQuery';
  if (lowerName.includes('dataproc')) return 'Dataproc';
  if (lowerName.includes('api key')) return 'API Keys';
  if (lowerName.includes('transparency')) return 'Access Transparency';
  if (lowerName.includes('contact')) return 'Essential Contacts';
  if (lowerName.includes('logging') || lowerName.includes('monitoring') || lowerName.includes('audit log')) return 'Logging & Monitoring';
  
  return sName || 'Other';
};

const providerOptions = [
  { value: 'aws', label: 'Amazon Web Services (AWS)' },
  { value: 'gcp', label: 'Google Cloud Platform (GCP)' },
  { value: 'azure', label: 'Microsoft Azure' },
];

const DashboardNavbar = () => {
  const { user, logout } = useContext(AuthContext);
  const [selectedProvider, setSelectedProvider] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [scanBackgroundStatus, setScanBackgroundStatus] = useState('idle'); // idle, scanning, completed
  const [profileOpen, setProfileOpen] = useState(false);
  const [theme, setTheme] = useState(localStorage.getItem('auditscope_theme') || 'light');
  const profileRef = useRef(null);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('auditscope_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => prev === 'light' ? 'dark' : 'light');
  };

  useEffect(() => {
    const handleScanComplete = (e) => {
      const results = e.detail;
      if (results && results.provider) {
        setSelectedProvider(results.provider);
      }
    };
    window.addEventListener('scanCompleted', handleScanComplete);
    return () => window.removeEventListener('scanCompleted', handleScanComplete);
  }, []);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (profileRef.current && !profileRef.current.contains(event.target)) {
        setProfileOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleScanClick = () => {
    if (selectedProvider) {
      setIsModalOpen(true);
    }
  };

  const handleScanComplete = (results) => {
    // Store in localStorage for DashboardPage to pick up when it mounts
    localStorage.setItem('last_viewed_scan', JSON.stringify(results));
    
    // Ensure Dashboard picks up the update if already mounted
    window.dispatchEvent(new CustomEvent('scanCompleted', { detail: results }));
    
    // Navigate to the Dashboard page directly
    window.history.pushState(null, '', '/dashboard');
    window.dispatchEvent(new Event('popstate'));
  };

  const getInitial = () => {
    if (user && user.name) return user.name.charAt(0).toUpperCase();
    if (user && user.email) return user.email.charAt(0).toUpperCase();
    return 'A';
  };

  return (
    <>
      <header className={styles.navbar}>
        <div className={styles.brand}>
          <div className={styles.logoIcon}>A</div>
          <div className={styles.logoText}>
            <span className={styles.logoMain}>Audit</span>
            <span className={styles.logoSub}>Scope</span>
          </div>
        </div>

        <div className={styles.mobileMenuToggle}>
          <span className={styles.hamburger}>☰</span>
        </div>

        <div className={styles.navControls}>
          <div className={styles.actionGroup}>
            {scanBackgroundStatus !== 'idle' && (
              <button 
                className={`${styles.scanIndicator} ${scanBackgroundStatus === 'completed' ? styles.scanIndicatorCompleted : ''}`} 
                onClick={() => setIsModalOpen(true)}
                title={scanBackgroundStatus === 'completed' ? "Scan Complete - View Results" : "Scan in Progress - View Details"}
              >
                {scanBackgroundStatus === 'completed' ? '✓' : ''}
              </button>
            )}

            <div data-tour="tour-navbar-provider">
              <Select
                options={providerOptions}
                value={selectedProvider}
                onChange={(e) => setSelectedProvider(e.target.value)}
                placeholder="Choose Provider..."
                className={styles.selectProvider}
              />
            </div>

            <div data-tour="tour-navbar-scan">
              <Button
                variant={selectedProvider ? "primary" : "secondary"}
                size="small"
                className={styles.scanBtn}
                disabled={!selectedProvider}
                onClick={handleScanClick}
                title={!selectedProvider ? "Please select a provider first" : "Start Audit Scan"}
              >
                Scan
              </Button>
            </div>

            <button 
              onClick={toggleTheme}
              title={theme === 'light' ? "Switch to Night Theme" : "Switch to Day Theme"}
              style={{ 
                background: 'none', 
                border: 'none', 
                cursor: 'pointer', 
                fontSize: '20px', 
                display: 'flex', 
                alignItems: 'center', 
                padding: '8px', 
                borderRadius: '50%',
                color: 'var(--color-text)',
                transition: 'background-color 0.2s',
                marginRight: '8px'
              }}
              onMouseOver={(e) => e.currentTarget.style.backgroundColor = 'var(--color-border)'}
              onMouseOut={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
            >
              {theme === 'light' ? (
                <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
              ) : (
                <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
              )}
            </button>

            <div
              data-tour="tour-navbar-profile"
              className={styles.userProfile}
              ref={profileRef}
              onClick={() => setProfileOpen(!profileOpen)}
              style={{ position: 'relative', cursor: 'pointer' }}
            >
              {user?.displayPicture ? (
                <img
                  src={user.displayPicture.startsWith('data:') ? user.displayPicture : `${window.location.hostname.includes('run.app') ? 'https://security-audit-accelerator-backend-196053730058.asia-south1.run.app' : 'https://security-audit-accelerator-backend-196053730058.asia-south1.run.app'}${user.displayPicture}`}
                  alt="Profile"
                  className={styles.avatar}
                />
              ) : (
                <div className={styles.avatar}>{getInitial()}</div>
              )}


              {profileOpen && (
                <div style={{ position: 'absolute', top: '100%', right: 0, marginTop: '8px', padding: '8px 0', backgroundColor: 'var(--color-bg-secondary)', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)', minWidth: '200px', boxShadow: '0 4px 16px rgba(0,0,0,0.12)', zIndex: 100 }}>
                  <div style={{ padding: '8px 16px', borderBottom: '1px solid var(--color-border)', marginBottom: '4px' }}>
                    <div style={{ fontWeight: 600, fontSize: 'var(--font-size-sm)', color: 'var(--color-text)' }}>{user?.name || 'User'}</div>
                    <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)' }}>{user?.email || ''}</div>
                  </div>
                  <button
                    onClick={(e) => { e.stopPropagation(); logout(); }}
                    style={{ width: '100%', textAlign: 'left', padding: '8px 16px', background: 'none', border: 'none', color: 'var(--color-danger)', cursor: 'pointer', fontSize: 'var(--font-size-sm)' }}
                  >
                    Log Out
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </header>

      <ScannerModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        provider={selectedProvider}
        onScanComplete={handleScanComplete}
        onScanStatusChange={setScanBackgroundStatus}
      />
    </>
  );
};

export default DashboardNavbar;
