import React, { useState, useEffect } from 'react';

import Card from '../../components/Card/Card';


const ScanHistoryPage = () => {
  const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:8000'
    : (window.location.hostname.includes('run.app') 
        ? 'https://cloud-security-audit.onrender.com' 
        : 'https://cloud-security-audit.onrender.com');

  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  // Filtering & Pagination State
  const [selectedProvider, setSelectedProvider] = useState('All');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 8;

  // Fetch all scans for the user on mount
  useEffect(() => {
    const fetchAllScans = async () => {
      setLoading(true);
      try {
        const token = localStorage.getItem('auditscope_token');
        const queryParams = new URLSearchParams(window.location.search);
        const projectIdParam = queryParams.get('project') || 'all';
        
        const res = await fetch(`${API_BASE}/api/projects/${projectIdParam}/scans`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await res.json();
        if (Array.isArray(data)) {
          setScans(data);
        } else {
          console.error('API did not return an array:', data);
          setScans([]);
        }
      } catch (err) {
        console.error('Failed to fetch scans:', err);
        setScans([]);
      } finally {
        setLoading(false);
      }
    };
    fetchAllScans();
  }, [API_BASE]);

  // Compute filtered and paginated scans
  const processedData = React.useMemo(() => {
    let filtered = Array.isArray(scans) ? scans : [];

    // Apply Provider Filter
    if (selectedProvider !== 'All') {
      filtered = filtered.filter(scan =>
        scan?.project?.provider?.toLowerCase() === selectedProvider.toLowerCase()
      );
    }

    // Calculate Pagination
    const totalPages = Math.ceil(filtered.length / itemsPerPage);
    const startIndex = (currentPage - 1) * itemsPerPage;
    const paginatedItems = filtered.slice(startIndex, startIndex + itemsPerPage);

    return {
      totalItems: filtered.length,
      items: paginatedItems,
      totalPages: totalPages
    };
  }, [scans, selectedProvider, currentPage]);

  const handlePageChange = (newPage) => {
    if (newPage >= 1 && newPage <= processedData.totalPages) {
      setCurrentPage(newPage);
    }
  };



  const openScanDetails = (scan) => {
    // Adapt scan history data to the format the dashboard expects
    const adaptedData = {
      score: scan.score,
      vulnerabilities: scan.findings || [],
      scanned: scan.scannedResources,
      provider: scan.project?.provider || 'gcp',
      dbProjectId: scan.projectId,
      isHistory: true // flag to indicate this is historical data
    };
    
    // Store in localStorage to pass to DashboardPage
    localStorage.setItem('last_viewed_scan', JSON.stringify(adaptedData));
    
    // Redirect to Dashboard
    window.location.href = '/dashboard';
  };

  return (
    <>
      <div style={{ paddingBottom: 'var(--spacing-4)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--spacing-6)' }}>
          <div>
            <h1 style={{ fontSize: 'var(--font-size-xl)', marginBottom: 'var(--spacing-1)' }}>Scan History</h1>
            <p style={{ color: 'var(--color-text-muted)', fontSize: 'var(--font-size-sm)', margin: 0 }}>
              Browse previous scan results across your cloud providers.
            </p>
          </div>
          <div style={{ display: 'flex', gap: 'var(--spacing-3)', alignItems: 'center' }}>
            <span style={{ fontSize: 'var(--font-size-sm)', color: 'var(--color-text-muted)' }}>Filter Provider:</span>
            <select
              value={selectedProvider}
              onChange={(e) => {
                setSelectedProvider(e.target.value);
                setCurrentPage(1); // reset pagination when filter changes
              }}
              style={{
                backgroundColor: 'var(--color-background-dark)',
                border: '1px solid var(--color-border)',
                borderRadius: '4px',
                padding: '6px 12px',
                color: 'var(--color-text)',
                fontSize: 'var(--font-size-sm)',
                cursor: 'pointer'
              }}
            >
              <option value="All" style={{ backgroundColor: '#1a1a1a', color: '#fff' }}>All Providers</option>
              <option value="gcp" style={{ backgroundColor: '#1a1a1a', color: '#fff' }}>Google Cloud (GCP)</option>
              <option value="aws" style={{ backgroundColor: '#1a1a1a', color: '#fff' }}>AWS</option>
              <option value="azure" style={{ backgroundColor: '#1a1a1a', color: '#fff' }}>Azure</option>
            </select>
          </div>
        </div>

        {loading ? (
          <div style={{ textAlign: 'center', color: 'var(--color-text-muted)', padding: 'var(--spacing-8)' }}>Loading scan history...</div>
        ) : processedData.totalItems === 0 ? (
          <Card style={{ minHeight: '200px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 'var(--spacing-3)' }}>
            <div style={{ opacity: 0.1, marginBottom: '10px' }}>
              <svg viewBox="0 0 24 24" width="60" height="60"><path fill="var(--color-primary)" d="M13 3c-4.97 0-9 4.03-9 9H1l3.89 3.89.07.14L9 12H6c0-3.87 3.13-7 7-7s7 3.13 7 7-3.13 7-7 7c-1.93 0-3.68-.79-4.94-2.06l-1.42 1.42C8.27 19.99 10.51 21 13 21c4.97 0 9-4.03 9-9s-4.03-9-9-9zm-1 5v5l4.28 2.54.72-1.21-3.5-2.08V8H12z"/></svg>
            </div>
            <h3 style={{ color: 'var(--color-text)' }}>No scans found</h3>
            <p style={{ color: 'var(--color-text-muted)', fontSize: 'var(--font-size-sm)' }}>
              {selectedProvider !== 'All'
                ? `No scan history matching the ${selectedProvider.toUpperCase()} provider filter.`
                : 'Run a multi-cloud security scan to see your history here!'}
            </p>
          </Card>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-3)' }}>
            {(processedData?.items || []).map((scan) => {
              if (!scan) return null;
              const safeProjectName = scan.project?.name || 'Cloud Project';
              const safeProvider = (scan.project?.provider || 'gcp').toUpperCase();
              const safeScore = typeof scan.score === 'number' ? scan.score : 0;
              const safeDate = scan.createdAt ? new Date(scan.createdAt) : new Date();

              return (
                <Card 
                  key={scan.id || Math.random()} 
                  style={{ padding: 'var(--spacing-4)', cursor: 'pointer', transition: 'border-color 0.2s, background-color 0.2s' }}
                  onClick={() => openScanDetails(scan)}
                  onMouseOver={(e) => e.currentTarget.style.borderColor = 'var(--color-primary)'}
                  onMouseOut={(e) => e.currentTarget.style.borderColor = 'var(--color-border)'}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--spacing-2)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--spacing-4)' }}>
                      <div style={{
                        fontSize: 'var(--font-size-xl)',
                        fontWeight: 800,
                        color: safeScore > 80 ? 'var(--color-success)' : safeScore > 50 ? '#eab308' : 'var(--color-danger)'
                      }}>
                        {safeScore}%
                      </div>
                      <div>
                        <div style={{ fontSize: 'var(--font-size-sm)', fontWeight: 600, color: 'var(--color-text)' }}>
                          {safeProjectName} <span style={{ color: 'var(--color-text-muted)', fontWeight: 400 }}>({safeProvider})</span>
                        </div>
                        <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)', marginTop: '4px' }}>
                          <span style={{ fontWeight: 500 }}>Date:</span> {safeDate.toLocaleDateString()} &nbsp;|&nbsp; <span style={{ fontWeight: 500 }}>Time:</span> {safeDate.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})} • {scan.scannedResources || 0} resources scanned
                        </div>
                      </div>
                    </div>
                  <div style={{ display: 'flex', gap: 'var(--spacing-3)', alignItems: 'center' }}>
                    {scan.criticalCount > 0 && (
                      <span style={{ fontSize: 'var(--font-size-xs)', padding: '4px 10px', borderRadius: '4px', backgroundColor: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)', color: '#ef4444', fontWeight: 600 }}>
                        {scan.criticalCount} Critical
                      </span>
                    )}
                    {scan.highCount > 0 && (
                      <span style={{ fontSize: 'var(--font-size-xs)', padding: '4px 10px', borderRadius: '4px', backgroundColor: 'rgba(249, 115, 22, 0.1)', border: '1px solid rgba(249, 115, 22, 0.2)', color: '#f97316', fontWeight: 600 }}>
                        {scan.highCount} High
                      </span>
                    )}
                    {scan.mediumCount > 0 && (
                      <span style={{ fontSize: 'var(--font-size-xs)', padding: '4px 10px', borderRadius: '4px', backgroundColor: 'rgba(234, 179, 8, 0.1)', border: '1px solid rgba(234, 179, 8, 0.2)', color: '#eab308', fontWeight: 600 }}>
                        {scan.mediumCount} Medium
                      </span>
                    )}
                  </div>
                  </div>
                </Card>
              );
            })}

            {/* Pagination Controls */}
            {processedData.totalPages > 1 && (
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 'var(--spacing-4)', paddingTop: 'var(--spacing-4)', borderTop: '1px solid var(--color-border)' }}>
                <div style={{ fontSize: 'var(--font-size-sm)', color: 'var(--color-text-muted)' }}>
                  Showing {((currentPage - 1) * itemsPerPage) + 1} to {Math.min(currentPage * itemsPerPage, processedData.totalItems)} of {processedData.totalItems} scans
                </div>
                <div style={{ display: 'flex', gap: 'var(--spacing-2)' }}>
                  <button
                    onClick={() => handlePageChange(currentPage - 1)}
                    disabled={currentPage === 1}
                    style={{
                      padding: '8px 16px', backgroundColor: 'transparent', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)',
                      color: currentPage === 1 ? 'var(--color-text-muted)' : 'var(--color-text)', cursor: currentPage === 1 ? 'not-allowed' : 'pointer'
                    }}
                  >
                    Previous
                  </button>
                  <button
                    onClick={() => handlePageChange(currentPage + 1)}
                    disabled={currentPage === processedData.totalPages}
                    style={{
                      padding: '8px 16px', backgroundColor: 'transparent', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-md)',
                      color: currentPage === processedData.totalPages ? 'var(--color-text-muted)' : 'var(--color-text)', cursor: currentPage === processedData.totalPages ? 'not-allowed' : 'pointer'
                    }}
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>


    </>
  );
};

export default ScanHistoryPage;
