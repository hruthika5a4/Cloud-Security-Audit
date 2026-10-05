import React, { useState, useRef } from 'react';
import styles from './ScannerModal.module.css';
import Button from '../Button/Button';

const ScannerModal = ({ isOpen, onClose, provider, onScanComplete, onScanStatusChange }) => {
  const [activeTab, setActiveTab] = useState('upload'); // 'upload' or 'paste'
  const [completedResults, setCompletedResults] = useState(null);
  const [file, setFile] = useState(null);
  const [jsonText, setJsonText] = useState('');

  // AWS State
  const [awsAccessKey, setAwsAccessKey] = useState('');
  const [awsSecretKey, setAwsSecretKey] = useState('');

  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [error, setError] = useState(null);

  const fileInputRef = useRef(null);

  if (!isOpen) return null;

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setFile(e.dataTransfer.files[0]);
      setError(null);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleStartScan = async () => {
    if (provider === 'gcp') {
      if (activeTab === 'upload' && !file) {
        setError("Please upload a JSON file first.");
        return;
      }
      if (activeTab === 'paste' && !jsonText.trim()) {
        setError("Please paste valid JSON credentials.");
        return;
      }
    } else if (provider === 'aws') {
      if (!awsAccessKey.trim() || !awsSecretKey.trim()) {
        setError("Please provide both Access Key ID and Secret Access Key.");
        return;
      }
    }

    localStorage.removeItem('latest_scan_result');
    localStorage.removeItem('last_viewed_scan');
    window.dispatchEvent(new CustomEvent('scanStarted'));

    setIsScanning(true);
    setScanProgress(0);
    setError(null);
    if (onScanStatusChange) onScanStatusChange('scanning');

    // Simulated progress tick (jumps every 500ms, slowing down as it reaches 99%)
    const progressInterval = setInterval(() => {
      setScanProgress(prev => {
         const remaining = 99 - prev;
         if (remaining <= 0) return 99;
         const jump = Math.max(1, Math.floor(remaining * 0.1));
         return prev + jump;
      });
    }, 500);

    const API_BASE = window.location.hostname.includes('run.app')
      ? 'https://cloud-security-audit.onrender.com' 
      : 'http://localhost:8000';
    try {
      const token = localStorage.getItem('auditscope_token');
      let response;

      if (provider === 'aws') {
        response = await fetch(`${API_BASE}/api/scan/aws`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify({
            accessKeyId: awsAccessKey.trim(),
            secretAccessKey: awsSecretKey.trim()
          }),
        });
      } else { // GCP
        if (activeTab === 'upload') {
          const formData = new FormData();
          formData.append('file', file);

          response = await fetch(`${API_BASE}/api/scan/gcp`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` },
            body: formData,
          });
        } else {
          response = await fetch(`${API_BASE}/api/scan/gcp`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ credentials: jsonText }),
          });
        }
      }

      if (!response.ok) {
        clearInterval(progressInterval);
        const errData = await response.json();
        throw new Error(errData.error || `Server responded with status: ${response.status}`);
      }

      setScanProgress(100);
      clearInterval(progressInterval);
      
      const rawResults = await response.json();

      const adaptedResults = {
        id: rawResults.dbScanId, // Store the DB ID for exports
        dbScanId: rawResults.dbScanId,
        dbProjectId: rawResults.dbProjectId,
        score: rawResults.summary.score,
        vulnerabilities: (rawResults.vulnerabilities || []).map(f => ({
          id: f.id,
          severity: f.severity,
          resource: f.resource,
          issue: f.issue,
          remediation: f.remediation
        })),
        scanned: rawResults.summary.scannedResources,
        provider: provider
      };

      if (onScanStatusChange) onScanStatusChange('completed');
      setCompletedResults(adaptedResults);
      localStorage.setItem('latest_scan_result', JSON.stringify(adaptedResults));
      window.dispatchEvent(new CustomEvent('scanCompleted', { detail: adaptedResults }));
      setIsScanning(false);

    } catch (err) {
      console.error("Scan Error:", err);
      clearInterval(progressInterval);
      setError(err.message || "Invalid JSON or network error. Ensure backend is running.");
      if (onScanStatusChange) onScanStatusChange('idle');
      setIsScanning(false);
      setScanProgress(0);
    }
  };

  return (
    <div className={styles.modalOverlay}>
      <div className={styles.modalContent}>

        {completedResults ? (
          <div className={styles.completionState}>
            <div className={styles.successIcon}>✓</div>
            <h2 className={styles.scanTitle}>Scan Complete</h2>
            <p className={styles.scanSubtitle}>Audit finished with {completedResults.vulnerabilities.length} vulnerabilities across {completedResults.scanned} resources.</p>
            <div style={{ marginTop: 'var(--spacing-6)' }}>
              <Button variant="primary" onClick={() => {
                onScanComplete(completedResults);
                setCompletedResults(null);
                if (onScanStatusChange) onScanStatusChange('idle');
                onClose();
              }}>View Results</Button>
            </div>
          </div>
        ) : isScanning ? (
          <div className={styles.scanningState}>
            <button className={styles.minimizeBtn} onClick={onClose} title="Minimize to background">−</button>
            <div className={styles.scannerRing}></div>
            <h2 className={styles.scanPercentage}>{scanProgress}%</h2>
            <h2 className={styles.scanTitle}>Auditing {provider.toUpperCase()} Infrastructure</h2>
            <p className={styles.scanSubtitle}>Analyzing IAM configurations, firewalls, and storage blobs...</p>
          </div>
        ) : (
          <>
            <div className={styles.header}>
              <h2 className={styles.title}>Scan {provider.toUpperCase()} Environment</h2>
              <button className={styles.closeBtn} onClick={onClose}>×</button>
            </div>

            <p className={styles.description}>
              {provider === 'aws'
                ? "Provide your AWS IAM User credentials to authorize the read-only security audit."
                : "Provide your Service Account Key to authorize the read-only security audit."
              }
            </p>

            {provider === 'aws' ? (
              <div className={styles.awsForm}>
                <div className={styles.formGroup}>
                  <label className={styles.awsLabel}>Access Key ID</label>
                  <input
                    type="text"
                    value={awsAccessKey}
                    onChange={(e) => setAwsAccessKey(e.target.value)}
                    placeholder="AKIAIOSFODNN7EXAMPLE"
                    className={styles.awsInput}
                  />
                </div>
                <div className={styles.formGroup}>
                  <label className={styles.awsLabel}>Secret Access Key</label>
                  <input
                    type="password"
                    value={awsSecretKey}
                    onChange={(e) => setAwsSecretKey(e.target.value)}
                    placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                    className={styles.awsInput}
                  />
                </div>
              </div>
            ) : (
              <>
                <div className={styles.tabs}>
                  <button
                    className={`${styles.tab} ${activeTab === 'upload' ? styles.activeTab : ''}`}
                    onClick={() => setActiveTab('upload')}
                  >
                    Upload File
                  </button>
                  <button
                    className={`${styles.tab} ${activeTab === 'paste' ? styles.activeTab : ''}`}
                    onClick={() => setActiveTab('paste')}
                  >
                    Paste JSON
                  </button>
                </div>

                <div className={styles.tabContent}>
                  {activeTab === 'upload' ? (
                    <div
                      className={styles.dropZone}
                      onDragOver={handleDragOver}
                      onDrop={handleDrop}
                      onClick={() => fileInputRef.current?.click()}
                    >
                      <input
                        type="file"
                        accept=".json"
                        style={{ display: 'none' }}
                        ref={fileInputRef}
                        onChange={handleFileChange}
                      />
                      <div className={styles.uploadIcon}>
                        {provider === 'aws' ? (
                          <svg viewBox="0 0 256 154" width="40" height="40"><path fill="var(--color-primary)" d="M128 32c-34 0-61 17-61 46 0 18 10 32 29 39-4 3-5 5-5 8 0 4 3 6 8 6 10 0 22-9 33-19 16 10 36 15 54 15 36 0 61-17 61-46 0-14-6-26-17-34-14-11-36-16-59-16l-43 1z"/></svg>
                        ) : provider === 'azure' ? (
                          <svg viewBox="0 0 24 24" width="40" height="40"><path fill="var(--color-primary)" d="M11.4 5.3l-8.5 13.4H12l2.6-4.1H7.8l5.2-8.3L11.4 5.3z M21.1 18.7l-9.7-15.4L8.8 7.4l6.4 11.3H21.1z"/></svg>
                        ) : (
                          <svg viewBox="0 0 24 24" width="40" height="40"><path fill="var(--color-primary)" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13h2v6h-2zm0 8h2v2h-2z" opacity="0.4"/><path fill="var(--color-primary)" d="M12 24a11.94 11.94 0 0 1-8.48-3.52l3.41-3.41c1.35.85 2.96 1.35 4.7 1.35 4.3 0 7.84-3.54 7.84-7.84S15.93 2.74 11.63 2.74a7.84 7.84 0 0 0-7.84 7.84c0 1.63.5 3.12 1.35 4.37h.37l-4.7 4.7C.32 17.5 0 14.85 0 12 0 5.37 5.37 0 12 0s12 5.37 12 12-5.37 12-12 12z"/></svg>
                        )}
                      </div>
                      {file ? (
                        <div className={styles.fileName}>{file.name}</div>
                      ) : (
                        <div>
                          <p className={styles.dropText}>Drag & Drop your .json file here</p>
                          <p className={styles.dropSubtext}>or click to browse</p>
                        </div>
                      )}
                    </div>
                  ) : (
                    <textarea
                      className={styles.jsonTextarea}
                      placeholder='{ "type": "service_account", "project_id": "..." }'
                      value={jsonText}
                      onChange={(e) => {
                        setJsonText(e.target.value);
                        setError(null);
                      }}
                      spellCheck="false"
                    />
                  )}
                </div>
              </>
            )}

            {error && <div className={styles.errorMsg}>{error}</div>}

            <div className={styles.footer}>
              <Button variant="ghost" onClick={onClose}>Cancel</Button>
              <Button variant="primary" onClick={handleStartScan}>Start Scan</Button>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default ScannerModal;
