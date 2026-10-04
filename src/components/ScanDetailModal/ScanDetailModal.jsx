import React from 'react';
import styles from './ScanDetailModal.module.css';

const ScanDetailModal = ({ isOpen, onClose, scan }) => {
  if (!isOpen || !scan) return null;

  const scoreColor = scan.score > 80 ? 'var(--color-success)' : scan.score > 50 ? '#eab308' : 'var(--color-danger)';
  const findings = scan.findings || [];

  const getSeverityStyle = (severity) => {
    switch (severity) {
      case 'Critical': return { color: '#ef4444', backgroundColor: 'rgba(239, 68, 68, 0.1)', padding: '2px 8px', borderRadius: '4px', fontWeight: 600 };
      case 'High': return { color: '#f97316', backgroundColor: 'rgba(249, 115, 22, 0.1)', padding: '2px 8px', borderRadius: '4px', fontWeight: 600 };
      case 'Medium': return { color: '#eab308', backgroundColor: 'rgba(234, 179, 8, 0.1)', padding: '2px 8px', borderRadius: '4px', fontWeight: 600 };
      default: return { color: '#3b82f6', backgroundColor: 'rgba(59, 130, 246, 0.1)', padding: '2px 8px', borderRadius: '4px', fontWeight: 600 };
    }
  };

  return (
    <div className={styles.modalOverlay} onClick={onClose}>
      <div className={styles.modalContent} onClick={e => e.stopPropagation()}>
        
        <div className={styles.header}>
          <div>
            <h2 className={styles.title}>{scan.project?.name || 'Scan Details'}</h2>
            <div className={styles.subtitle}>
              {new Date(scan.createdAt).toLocaleString()} • {scan.project?.provider?.toUpperCase() || 'Provider'}
            </div>
          </div>
          <button className={styles.closeBtn} onClick={onClose}>&times;</button>
        </div>

        <div className={styles.summaryCards}>
          <div className={styles.sCard}>
            <div className={styles.sCardValue} style={{ color: scoreColor }}>{scan.score}%</div>
            <div className={styles.sCardLabel}>Security Score</div>
          </div>
          <div className={styles.sCard}>
            <div className={styles.sCardValue} style={{ color: 'var(--color-text)' }}>{findings.length}</div>
            <div className={styles.sCardLabel}>Vulnerabilities Found</div>
          </div>
          <div className={styles.sCard}>
            <div className={styles.sCardValue} style={{ color: 'var(--color-text)' }}>{scan.criticalCount + scan.highCount}</div>
            <div className={styles.sCardLabel}>Critical / High Issues</div>
          </div>
          <div className={styles.sCard}>
            <div className={styles.sCardValue} style={{ color: 'var(--color-text)' }}>{scan.scannedResources}</div>
            <div className={styles.sCardLabel}>Resources Scanned</div>
          </div>
        </div>

        <div className={styles.tableContainer}>
          <table className={styles.vulnTable}>
            <thead>
              <tr>
                <th style={{ width: '10%' }}>Severity</th>
                <th style={{ width: '30%' }}>Resource</th>
                <th style={{ width: '30%' }}>Issue Description</th>
                <th style={{ width: '30%' }}>Recommendation</th>
              </tr>
            </thead>
            <tbody>
              {findings.length > 0 ? findings.map((vuln, idx) => (
                <tr key={idx}>
                  <td>
                    <span style={getSeverityStyle(vuln.severity)}>{vuln.severity}</span>
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.85em' }}>{vuln.resource || '-'}</td>
                  <td>{vuln.issue || '-'}</td>
                  <td style={{ color: 'var(--color-primary)', opacity: 0.9 }}>{vuln.remediation || '-'}</td>
                </tr>
              )) : (
                <tr>
                  <td colSpan="3" style={{ textAlign: 'center', padding: '2rem', color: 'var(--color-text-muted)' }}>
                    No vulnerabilities found! Great job.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

      </div>
    </div>
  );
};

export default ScanDetailModal;
