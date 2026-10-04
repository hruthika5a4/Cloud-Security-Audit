import React, { useState, useEffect } from 'react';
import Card from '../../components/Card/Card';

const PROVIDER_META = {
  gcp:   { label: 'Google Cloud',       color: '#4285F4', bg: 'rgba(66,133,244,0.10)',   icon: <svg viewBox="0 0 24 24" width="22" height="22"><path fill="#4285F4" d="M12 2L4.5 20.29l.71.71L12 18l6.79 3 .71-.71L12 2z"/></svg> },
  aws:   { label: 'Amazon Web Services', color: '#FF9900', bg: 'rgba(255,153,0,0.10)',    icon: <svg viewBox="0 0 256 154" width="22" height="22"><path fill="#232F3E" d="M128 32c-34 0-61 17-61 46 0 18 10 32 29 39-4 3-5 5-5 8 0 4 3 6 8 6 10 0 22-9 33-19 16 10 36 15 54 15 36 0 61-17 61-46 0-14-6-26-17-34-14-11-36-16-59-16l-43 1z"/><path fill="#FF9900" d="M128 0c-45 0-82 25-82 56 0 20 16 38 41 48-12 13-33 24-58 29-5 1-4 3 1 3 45 0 86-21 106-53 23 10 49 16 77 16 45 0 82-25 82-56S259 0 214 0c-26 0-48 7-66 18C132 8 111 0 86 0z"/></svg> },
  azure: { label: 'Microsoft Azure',     color: '#0078D4', bg: 'rgba(0,120,212,0.10)',    icon: <svg viewBox="0 0 24 24" width="22" height="22"><path fill="#0072C6" d="M11.4 5.3l-8.5 13.4H12l2.6-4.1H7.8l5.2-8.3L11.4 5.3z M21.1 18.7l-9.7-15.4L8.8 7.4l6.4 11.3H21.1z"/></svg> },
};

const scoreColor = (s) => {
  if (s == null) return '#6b7280';
  if (s > 80) return '#22c55e';
  if (s > 50) return '#eab308';
  return '#ef4444';
};

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div style={{ background: 'var(--color-bg)', border: '1px solid var(--color-border)', padding: '8px 12px', borderRadius: '8px', boxShadow: 'var(--shadow-md)' }}>
        <p style={{ margin: '0 0 4px 0', fontSize: '10px', color: 'var(--color-text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Scan Date: {label}</p>
        <p style={{ margin: 0, fontSize: '14px', fontWeight: 800, color: 'var(--color-primary)' }}>
          Score: {payload[0].value}%
        </p>
      </div>
    );
  }
  return null;
};

const StatCard = ({ label, value, icon, accent, trend, tooltip }) => (
  <div style={{
    background: 'var(--color-bg-secondary)',
    border: '1px solid var(--color-border)',
    borderRadius: 10,
    padding: '10px 14px',
    display: 'flex', flexDirection: 'column', gap: 3,
    flex: 1, minWidth: 0, position: 'relative', overflow: 'hidden',
  }}>
    <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: '2px', background: accent, borderRadius: '10px 10px 0 0' }} />
    <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'flex-start' }}>
      {tooltip && (
        <div style={{ cursor: 'help', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: 14, height: 14, borderRadius: '50%', background: 'var(--color-border)', color: 'var(--color-text-muted)', fontSize: 10, fontWeight: 700 }} title={tooltip}>
          ?
        </div>
      )}
    </div>
    <div style={{ display: 'flex', alignItems: 'flex-end', gap: 6, marginTop: tooltip ? -4 : 4 }}>
      <div style={{ fontSize: 17, fontWeight: 800, color: 'var(--color-text)', lineHeight: 1 }}>{value}</div>
      {trend && (
        <div style={{ fontSize: 10, fontWeight: 700, color: trend.color, paddingBottom: 1 }}>
          {trend.icon} {trend.text}
        </div>
      )}
    </div>
    <div style={{ fontSize: 10, color: 'var(--color-text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</div>
  </div>
);

const ProjectDetailsPage = ({ projectId }) => {
  const API_BASE = window.location.hostname.includes('run.app')
    ? 'https://security-audit-accelerator-backend-196053730058.asia-south1.run.app' 
    : 'http://localhost:8000';

  const [project,  setProject]  = useState(null);
  const [scans,    setScans]    = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [dlStatus, setDlStatus] = useState('idle'); // idle | downloading | done | error

  useEffect(() => {
    const go = async () => {
      setLoading(true);
      try {
        const token = localStorage.getItem('auditscope_token');
        const h = { 'Authorization': `Bearer ${token}` };

        const projRes = await fetch(`${API_BASE}/api/projects/${projectId}`, { headers: h });
        if (!projRes.ok) throw new Error('Not found');
        const projData = await projRes.json();
        setProject(projData);

        const scanRes  = await fetch(`${API_BASE}/api/projects/all/scans`, { headers: h });
        const allScans = await scanRes.json();
        if (Array.isArray(allScans)) {
          setScans(allScans.filter(s => s.project && s.project.name === projData.name));
        } else {
          console.error('Scans API did not return an array:', allScans);
          setScans([]);
        }
      } catch (e) { console.error(e); }
      finally { setLoading(false); }
    };
    go();
  }, [projectId]);

  const latest = scans[0] || null;
  const totalScans = scans.length;
  
  // Current stats relative to the latest scan
  const currentScore = latest?.score ?? null;
  const currentResources = latest?.scannedResources || 0;
  const currentCritical = latest?.criticalCount || 0;
  const currentHigh = latest?.highCount || 0;
  const currentMedium = latest?.mediumCount || 0;
  const currentTotalIssues = currentCritical + currentHigh + currentMedium;

  // New Coverage Stats
  const latestSkippedRaw = latest?.skippedChecks ? JSON.parse(latest.skippedChecks) : [];
  const totalChecks = latest?.totalChecks || 77; // Default to the new 77-checkpoint standard
  const skippedCount = latestSkippedRaw.length;
  const completedCount = totalChecks - skippedCount;
  const coveragePercent = Math.round((completedCount / totalChecks) * 100);

  // Previous stats for trend computation
  const previous = scans[1] || null;
  const prevScore = previous?.score ?? null;
  const prevTotalIssues = previous ? (previous.criticalCount + previous.highCount + previous.mediumCount) : null;

  // Helpers for Trend Arrows
  const getScoreTrend = () => {
    if (currentScore === null || prevScore === null) return null;
    const diff = currentScore - prevScore;
    if (diff > 0) return { text: `${diff}%`, icon: '↑', color: '#22c55e' }; // Score Up is Good
    if (diff < 0) return { text: `${Math.abs(diff)}%`, icon: '↓', color: '#ef4444' };
    return { text: 'unchanged', icon: '–', color: 'var(--color-text-muted)' };
  };

  const getIssuesTrend = () => {
    if (currentTotalIssues === null || prevTotalIssues === null) return null;
    const diff = currentTotalIssues - prevTotalIssues;
    if (diff > 0) return { text: `${diff} new`, icon: '↑', color: '#ef4444' }; // Issues Up is Bad
    if (diff < 0) return { text: `${Math.abs(diff)} fixed`, icon: '↓', color: '#22c55e' };
    return { text: 'unchanged', icon: '–', color: 'var(--color-text-muted)' };
  };

  // ── Download Project Summary PDF ─────────────────────────────────
  const handleDownloadReport = async () => {
    if (!project) return;
    setDlStatus('downloading');

    try {
      const payload = {
        projectName:    project.name,
        projectId:      project._id || project.id || project.name,
        provider:       project.provider,
        createdAt:      project.createdAt,
        totalScans,
        latestScore:    currentScore,
        totalResources: currentResources,
        totalIssues:    currentTotalIssues,
        totalCritical:  currentCritical,
        totalHigh:      currentHigh,
        totalMedium:    currentMedium,
        scoreHistory:   lineData, // The trend line data
        recentScans:    scans.slice(0, 10).map(s => ({ // Send top 10 for the PDF list
          score: s.score,
          date: new Date(s.createdAt).toLocaleDateString(),
          time: new Date(s.createdAt).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}),
          resources: s.scannedResources,
          critical: s.criticalCount,
          high: s.highCount,
          medium: s.mediumCount
        }))
      };

      const token = localStorage.getItem('auditscope_token');
      const res = await fetch(`${API_BASE}/api/reports/project-summary`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body:    JSON.stringify(payload),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to generate PDF');
      }

      const blob = await res.blob();
      const url  = window.URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = `AuditScope_${project.name}_Summary_${new Date().toISOString().slice(0, 10)}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      setDlStatus('done');
      setTimeout(() => setDlStatus('idle'), 3000);
    } catch (err) {
      console.error('[Download]', err);
      setDlStatus('error');
      setTimeout(() => setDlStatus('idle'), 4000);
    }
  };

  // ──────────────────────────────────────────────────────────────────
  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '50vh', flexDirection: 'column', gap: 12 }}>
      <div style={{ width: 36, height: 36, borderRadius: '50%', border: '4px solid var(--color-border)', borderTopColor: 'var(--color-primary)', animation: 'spin 0.8s linear infinite' }} />
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
      <p style={{ color: 'var(--color-text-muted)', fontSize: 13 }}>Loading…</p>
    </div>
  );

  if (!project) return (
    <div style={{ textAlign: 'center', padding: 60, color: 'var(--color-danger)', fontSize: 13 }}>Project not found.</div>
  );

  const prov = PROVIDER_META[project.provider] || PROVIDER_META.gcp;

  // Line chart requires oldest to newest (left to right chronological)
  const lineData = [...scans].reverse().map(s => {
    const d = new Date(s.createdAt);
    const shortDate = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    return { label: shortDate, value: s.score || 0 };
  });

  const dlLabel = dlStatus === 'downloading' ? '⏳ Generating PDF...'
                : dlStatus === 'done'        ? '✅ Downloaded!'
                : dlStatus === 'error'       ? '❌ Failed'
                : '⬇ Download Report';

  return (
    <>
      <style>{`
        .pd-card { transition: transform 0.15s, box-shadow 0.15s; }
        .pd-card:hover { transform: translateY(-2px); box-shadow: 0 6px 18px rgba(0,0,0,0.10); }
        .pd-btn  { transition: opacity 0.15s, transform 0.15s; }
        .pd-btn:hover  { opacity: 0.88; transform: translateY(-1px); }
      `}</style>

      <div style={{ paddingBottom: 32 }}>

        {/* Back */}
        <a href="/dashboard/projects" style={{ display: 'inline-flex', alignItems: 'center', gap: 5, color: 'var(--color-text-muted)', textDecoration: 'none', fontSize: 12, marginBottom: 16, fontWeight: 500 }}>
          <span>←</span> Back to Projects
        </a>

        {/* ── Header ── */}
        <div style={{
          background: `linear-gradient(130deg, ${prov.bg} 0%, var(--color-bg-secondary) 100%)`,
          border: '1px solid var(--color-border)', borderRadius: 14,
          padding: '18px 22px', marginBottom: 18,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{ width: 46, height: 46, borderRadius: 12, background: prov.bg, border: `1.5px solid ${prov.color}30`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 22 }}>
              {prov.icon}
            </div>
            <div>
              <h1 style={{ fontSize: '0.95rem', fontWeight: 800, margin: 0, color: 'var(--color-text)' }}>{project.name}</h1>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
                <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', padding: '2px 8px', borderRadius: 99, background: prov.bg, color: prov.color, border: `1px solid ${prov.color}40` }}>
                  {prov.label}
                </span>
                <span style={{ fontSize: 11, color: 'var(--color-text-muted)' }}>
                  Created {new Date(project.createdAt).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })}
                </span>
              </div>
            </div>
          </div>

          {/* ── Download Report button ── */}
          {latest && (
            <button
              className="pd-btn"
              onClick={handleDownloadReport}
              disabled={dlStatus === 'downloading'}
              style={{
                padding: '8px 18px', borderRadius: 8, border: 'none', cursor: dlStatus === 'downloading' ? 'wait' : 'pointer',
                background: dlStatus === 'done'  ? '#22c55e'
                          : dlStatus === 'error' ? '#ef4444'
                          : 'var(--color-primary)',
                color: '#fff', fontWeight: 700, fontSize: 12,
                display: 'flex', alignItems: 'center', gap: 6,
                transition: 'all 0.2s',
                opacity: dlStatus === 'downloading' ? 0.7 : 1,
              }}
            >
              {dlLabel}
            </button>
          )}
        </div>

        {/* ── Row 1: 4 Stat cards — now using Latest + Trend stats ── */}
        <div style={{ display: 'flex', gap: 12, marginBottom: 12, flexWrap: 'wrap' }}>
          <div className="pd-card" style={{ flex: 1, minWidth: 120 }}>
            <StatCard label="Total Scans"    value={totalScans.toLocaleString()}                              icon="🔍" accent="#6366f1" tooltip="The total number of security audits performed on this project since creation." />
          </div>
          <div className="pd-card" style={{ flex: 1, minWidth: 120 }}>
            <StatCard label="Latest Score"   value={latest ? `${currentScore}%` : '—'}      icon="🛡️" accent={scoreColor(currentScore)} trend={getScoreTrend()} tooltip="The health percentage of your cloud environment during the most recent audit. A higher score means better security. Green arrow means you're improving!" />
          </div>
          <div className="pd-card" style={{ flex: 1, minWidth: 120 }}>
            <StatCard label="Latest Resources" value={currentResources.toLocaleString()}        icon="🖥️" accent="#10b981" tooltip="The total number of cloud resources assessed during the most recent scan." />
          </div>
          <div className="pd-card" style={{ flex: 1, minWidth: 120 }}>
            <StatCard label="Active Issues"   value={currentTotalIssues.toLocaleString()}            icon="⚠️" accent={currentTotalIssues > 0 ? '#ef4444' : '#22c55e'} trend={getIssuesTrend()} tooltip="The total number of open vulnerabilities (Critical, High, and Medium) detected in the most recent scan." />
          </div>
          <div className="pd-card" style={{ flex: 1, minWidth: 120 }}>
            <StatCard 
              label="Audit Coverage"   
              value={latest ? `${coveragePercent}%` : '—'} 
              icon="⚖️" 
              accent={coveragePercent > 90 ? '#22c55e' : coveragePercent > 70 ? '#eab308' : '#ef4444'} 
              tooltip={`This audit successfully executed ${completedCount.toLocaleString()} out of ${totalChecks.toLocaleString()} individual security validations across your resources. ${skippedCount > 0 ? `${skippedCount} validations were skipped due to service availability.` : 'Audit depth is 100%!'}`} 
            />
          </div>
        </div>

        {/* ── Row 2: Historical Score Trend chart ── */}
        {scans.length > 0 && (
          <div style={{
            background: 'var(--color-bg-secondary)',
            border: '1px solid var(--color-border)',
            borderRadius: 10, padding: '12px 16px',
            display: 'flex', flexDirection: 'column', gap: 8
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <div>
                <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--color-text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
                  Historical Security Score Trend
                  <span style={{ cursor: 'help', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: 14, height: 14, borderRadius: '50%', background: 'var(--color-border)', color: 'var(--color-text-muted)', fontSize: 10 }} title="Shows your Security Score percentage (0-100%) tracking chronologically across scans. An upward slope indicates improved security posture where vulnerabilities are being fixed faster than new ones appear.">?</span>
                </span>
                <span style={{ fontSize: 10, color: 'var(--color-text-muted)', marginLeft: 8 }}>
                  (across {totalScans} scan{totalScans !== 1 ? 's' : ''})
                </span>
              </div>
              <div style={{ display: 'flex', gap: 14, alignItems: 'center' }}>
                <span style={{ fontSize: 11, color: 'var(--color-primary)', fontWeight: 700 }}>
                  <span style={{ display: 'inline-block', width: 12, height: 2, background: 'var(--color-primary)', marginRight: 4, verticalAlign: 'middle' }} />
                  Security Score
                </span>
              </div>
            </div>
            <div style={{ width: '100%', height: 260 }}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={lineData} margin={{ top: 10, right: 10, left: -5, bottom: 15 }}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--color-border)" />
                  <XAxis 
                    dataKey="label" 
                    axisLine={false} 
                    tickLine={false} 
                    tick={{ fontSize: 10, fill: 'var(--color-text-muted)' }} 
                    dy={10} 
                    label={{ value: 'Scan Timeline', position: 'insideBottom', offset: -10, fill: 'var(--color-text-muted)', fontSize: 10, fontWeight: 600, letterSpacing: '0.05em', textTransform: 'uppercase' }}
                  />
                  <YAxis 
                    domain={[0, 100]} 
                    axisLine={false} 
                    tickLine={false} 
                    tick={{ fontSize: 10, fill: 'var(--color-text-muted)' }} 
                    label={{ value: 'Score (%)', angle: -90, position: 'insideLeft', offset: 12, fill: 'var(--color-text-muted)', fontSize: 10, fontWeight: 600, letterSpacing: '0.05em', textTransform: 'uppercase' }}
                  />
                  <Tooltip content={<CustomTooltip />} cursor={{ stroke: 'var(--color-border)', strokeWidth: 1, strokeDasharray: '3 3' }} />
                  <Line 
                    type="monotone" 
                    dataKey="value" 
                    stroke="var(--color-primary)" 
                    strokeWidth={3}
                    dot={{ fill: 'var(--color-bg)', strokeWidth: 2, r: 4, stroke: 'var(--color-primary)' }}
                    activeDot={{ r: 6, strokeWidth: 0, fill: 'var(--color-primary)' }}
                    animationDuration={1500}
                    isAnimationActive={true}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}
        {/* ── Row 3: Local Scan History Logs ── */}
        {scans.length > 0 && (
          <div style={{ marginTop: '32px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
               <h3 style={{ fontSize: '13px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--color-text-muted)', margin: 0 }}>Project Scan History</h3>
            </div>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--spacing-3)' }}>
              {scans.map((scan) => {
                const safeScore = typeof scan.score === 'number' ? scan.score : 0;
                const safeDate = new Date(scan.createdAt);
                
                const openScanDetails = (scanToOpen) => {
                  const adaptedData = {
                    score: scanToOpen.score,
                    vulnerabilities: scanToOpen.findings || [],
                    scanned: scanToOpen.scannedResources,
                    provider: project.provider || 'gcp',
                    dbProjectId: scanToOpen.projectId || project._id || project.id,
                    isHistory: true
                  };
                  localStorage.setItem('last_viewed_scan', JSON.stringify(adaptedData));
                  window.location.href = '/dashboard';
                };

                return (
                  <Card 
                    key={scan._id || scan.id || Math.random()} 
                    onClick={() => openScanDetails(scan)}
                    style={{ padding: 'var(--spacing-4)', transition: 'border-color 0.2s, background-color 0.2s', cursor: 'pointer' }}
                    onMouseOver={(e) => e.currentTarget.style.borderColor = 'var(--color-primary)'}
                    onMouseOut={(e) => e.currentTarget.style.borderColor = 'var(--color-border)'}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
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
                            {project.name} <span style={{ color: 'var(--color-text-muted)', fontWeight: 400 }}>({prov.label})</span>
                          </div>
                          <div style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)', marginTop: '4px' }}>
                            <span style={{ fontWeight: 500 }}>Date:</span> {safeDate.toLocaleDateString()} &nbsp;|&nbsp; <span style={{ fontWeight: 500 }}>Time:</span> {safeDate.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})} • {scan.scannedResources || 0} resources scanned
                          </div>
                        </div>
                      </div>
                      
                      <div style={{ display: 'flex', gap: 'var(--spacing-3)', alignItems: 'center' }}>
                        {currentCritical > 0 && scan.criticalCount > 0 && (
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

                    {/* New: Skipped Checks Display */}
                    {scan.skippedChecks && JSON.parse(scan.skippedChecks).length > 0 && (
                      <div style={{ marginTop: 12, paddingTop: 12, borderTop: '1px solid var(--color-border)', fontSize: '11px' }}>
                        <div style={{ color: '#ca8a04', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                          <span>🛡️</span> {JSON.parse(scan.skippedChecks).length} CHECK(S) SKIPPED
                        </div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                          {JSON.parse(scan.skippedChecks).map((skip, sidx) => (
                            <div key={sidx} style={{ background: 'var(--color-bg-secondary)', padding: '4px 8px', borderRadius: 4, border: '1px solid var(--color-border)', color: 'var(--color-text-muted)' }}>
                              <strong style={{ color: 'var(--color-text)' }}>{skip.service}:</strong> {skip.reason}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </Card>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </>
  );
};

export default ProjectDetailsPage;
