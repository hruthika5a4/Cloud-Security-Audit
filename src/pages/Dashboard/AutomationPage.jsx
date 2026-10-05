import React, { useState, useEffect, useCallback, useRef } from 'react';

import Card from '../../components/Card/Card';
import Button from '../../components/Button/Button';
import ScheduleModal from '../../components/ScheduleModal/ScheduleModal';

const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' ? 'http://localhost:8000' : 'https://cloud-security-audit.onrender.com';
const POLL_INTERVAL_MS = 30000; // 30 seconds

const AutomationPage = () => {
  const [schedules, setSchedules] = useState([]);
  const [projects, setProjects] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [selectedProject, setSelectedProject] = useState(null);
  const [runningIds, setRunningIds] = useState(new Set());
  const pollTimerRef = useRef(null);

  const fetchData = useCallback(async (isManual = false) => {
    if (isManual) setRefreshing(true);
    else if (schedules.length === 0) setLoading(true);

    try {
      const token = localStorage.getItem('auditscope_token');
      const [schedRes, projRes] = await Promise.all([
        fetch(`${API_BASE}/api/schedules`, {
          headers: { 'Authorization': `Bearer ${token}` }
        }),
        fetch(`${API_BASE}/api/projects/all`, {
            headers: { 'Authorization': `Bearer ${token}` }
        })
      ]);

      if (schedRes.ok) {
        const schedData = await schedRes.json();
        if (Array.isArray(schedData)) {
          setSchedules(schedData);
        } else {
          console.error('Schedules API did not return an array:', schedData);
          setSchedules([]);
        }
      }
      if (projRes.ok) {
        const projData = await projRes.json();
        if (Array.isArray(projData)) {
          setProjects(projData);
        } else {
          console.error('Projects API did not return an array:', projData);
          setProjects([]);
        }
      }
      setLastUpdated(new Date());
    } catch (err) {
      console.error('Failed to fetch automation data', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [schedules.length]);

  // Initial load
  useEffect(() => {
    fetchData();
  }, []);

  // Set up polling every 30 seconds to auto-refresh Next Run / Last Run
  useEffect(() => {
    pollTimerRef.current = setInterval(() => {
      fetchData(false);
    }, POLL_INTERVAL_MS);

    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, []);

  const toggleSchedule = async (id) => {
    try {
      const token = localStorage.getItem('auditscope_token');
      await fetch(`${API_BASE}/api/schedules/${id}/toggle`, {
        method: 'PATCH',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      fetchData(true);
    } catch (err) {
      console.error('Toggle failed', err);
    }
  };

  const deleteSchedule = async (id) => {
    if (!window.confirm('Are you sure you want to remove this automation?')) return;
    try {
      const token = localStorage.getItem('auditscope_token');
      await fetch(`${API_BASE}/api/schedules/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      fetchData(true);
    } catch (err) {
      console.error('Delete failed', err);
    }
  };
  
  const handleRunNow = async (id) => {
    setRunningIds(prev => new Set(prev).add(id));
    try {
      const token = localStorage.getItem('auditscope_token');
      const res = await fetch(`${API_BASE}/api/schedules/${id}/run`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        alert('Audit triggered! A fresh report will be sent to your email list momentarily.');
        fetchData(true);
      } else {
        const err = await res.json();
        alert(`Failed to trigger: ${err.error || 'Unknown error'}`);
      }
    } catch (err) {
      console.error('Run Now failed', err);
      alert('Network error. Failed to trigger automation.');
    } finally {
      setRunningIds(prev => {
        const newSet = new Set(prev);
        newSet.delete(id);
        return newSet;
      });
    }
  };

  const handleCreateNew = () => {
    setSelectedProject(null);
    setIsModalOpen(true);
  };

  const formatDateTime = (dateStr) => {
    if (!dateStr) return 'Never';
    try {
      return new Date(dateStr).toLocaleString([], { 
        dateStyle: 'medium', 
        timeStyle: 'short' 
      });
    } catch {
      return 'Invalid date';
    }
  };

  const getNextRunStatus = (nextRunStr, isActive) => {
    if (!isActive) return { label: 'Paused', color: '#ef4444' };
    if (!nextRunStr) return { label: 'Not set', color: 'var(--color-text-muted)' };
    const diff = new Date(nextRunStr) - new Date();
    const hours = Math.floor(diff / 3600000);
    const mins = Math.floor((diff % 3600000) / 60000);
    if (diff < 0) return { label: 'Pending...', color: '#f59e0b' };
    if (hours < 1) return { label: `in ${mins}m`, color: '#22c55e' };
    if (hours < 24) return { label: `in ${hours}h ${mins}m`, color: '#22c55e' };
    return { label: formatDateTime(nextRunStr), color: 'var(--color-text)' };
  };

  return (
    <>
      <div style={{ paddingBottom: 'var(--spacing-8)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--spacing-8)' }}>
          <div>
            <h1 style={{ fontSize: 'var(--font-size-3xl)', marginBottom: 'var(--spacing-1)' }}>Automation Hub</h1>
            <p style={{ color: 'var(--color-text-muted)', margin: 0 }}>
              Manage your scheduled security audits and automated reporting.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
            {/* Manual refresh button */}
            <button
              onClick={() => fetchData(true)}
              disabled={refreshing}
              title="Refresh schedule status"
              style={{
                padding: '10px 14px',
                borderRadius: '8px',
                background: 'var(--color-bg-secondary)',
                border: '1px solid var(--color-border)',
                color: 'var(--color-text-muted)',
                cursor: 'pointer',
                fontSize: '13px',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                transition: 'all 0.2s',
                opacity: refreshing ? 0.6 : 1
              }}
            >
              <span style={{ 
                display: 'inline-block',
                animation: refreshing ? 'spin 1s linear infinite' : 'none'
              }}>↻</span>
              {lastUpdated ? `Updated ${new Date(lastUpdated).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : 'Refresh'}
            </button>
            <Button variant="primary" onClick={handleCreateNew}>
              + New Automation
            </Button>
          </div>
        </div>

        {loading ? (
          <div style={{ textAlign: 'center', color: 'var(--color-text-muted)', padding: '60px' }}>Loading automations...</div>
        ) : schedules.length === 0 ? (
          <Card style={{ minHeight: '300px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 'var(--spacing-4)', borderStyle: 'dashed', background: 'var(--color-bg-secondary)', boxShadow: '0 4px 12px rgba(0,0,0,0.08)' }}>
            <div style={{ opacity: 0.1, marginBottom: '10px' }}>
              <svg viewBox="0 0 24 24" width="80" height="80"><path fill="var(--color-primary)" d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z"/></svg>
            </div>
            <h3 style={{ margin: 0 }}>No active automations</h3>
            <p style={{ color: 'var(--color-text-muted)', textAlign: 'center', maxWidth: '350px' }}>
              Schedule recurring audits to keep your cloud infrastructure secure without manual effort.
            </p>
            <Button variant="secondary" onClick={handleCreateNew}>Get Started</Button>
          </Card>
        ) : (
          <>
            {/* Auto-refresh indicator */}
            <div style={{ 
              display: 'flex', alignItems: 'center', gap: '8px',
              fontSize: '12px', color: 'var(--color-text-muted)', 
              marginBottom: 'var(--spacing-4)'
            }}>
              <span style={{ 
                width: '6px', height: '6px', borderRadius: '50%', 
                background: '#22c55e', display: 'inline-block',
                boxShadow: '0 0 6px #22c55e'
              }}></span>
              Auto-refreshing every 30 seconds to track Next Run &amp; Last Run
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: 'var(--spacing-6)' }}>
              {schedules.map((schedule) => {
                const nextRunStatus = getNextRunStatus(schedule.nextRun, schedule.isActive);
                return (
                  <Card 
                    key={schedule.id} 
                    style={{ 
                      padding: 'var(--spacing-6)', 
                      position: 'relative', 
                      border: `1px solid ${schedule.isActive ? 'rgba(34,197,94,0.15)' : 'var(--color-border)'}`, 
                      background: schedule.isActive ? 'rgba(34, 197, 94, 0.02)' : 'var(--color-bg-secondary)', 
                      boxShadow: '0 4px 16px rgba(0,0,0,0.08)',
                      transition: 'all 0.3s'
                    }}
                  >
                    {/* Left accent bar */}
                    <div style={{ 
                      position: 'absolute', left: 0, top: 0, bottom: 0, width: '4px', borderRadius: '8px 0 0 8px',
                      background: schedule.isActive 
                        ? 'linear-gradient(180deg, #22c55e, #16a34a)' 
                        : 'rgba(239,68,68,0.3)'
                    }}></div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 'var(--spacing-4)', paddingLeft: '8px' }}>
                      <div>
                        <span style={{ 
                            fontSize: '10px', fontWeight: 700, padding: '2px 8px', borderRadius: '4px', 
                            background: schedule.isActive ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                            color: schedule.isActive ? '#22c55e' : '#ef4444', textTransform: 'uppercase', letterSpacing: '0.05em'
                        }}>
                          {schedule.isActive ? '● Active' : '◎ Paused'}
                        </span>
                        <h3 style={{ margin: '8px 0 4px 0', fontSize: 'var(--font-size-xl)' }}>{schedule.project?.name || 'Automated Scan'}</h3>
                        <p style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)', margin: 0, textTransform: 'uppercase' }}>
                          {schedule.project?.provider?.toUpperCase() || 'GCP'} • {schedule.frequency}
                        </p>
                      </div>
                      <div style={{ display: 'flex' }}>
                        {schedule.project?.provider === 'aws' ? (
                          <svg viewBox="0 0 256 154" width="24" height="24"><path fill="#FF9900" d="M128 32c-34 0-61 17-61 46 0 18 10 32 29 39-4 3-5 5-5 8 0 4 3 6 8 6 10 0 22-9 33-19 16 10 36 15 54 15 36 0 61-17 61-46 0-14-6-26-17-34-14-11-36-16-59-16l-43 1z"/><path fill="#FF9900" d="M128 0c-45 0-82 25-82 56 0 20 16 38 41 48-12 13-33 24-58 29-5 1-4 3 1 3 45 0 86-21 106-53 23 10 49 16 77 16 45 0 82-25 82-56S259 0 214 0c-26 0-48 7-66 18C132 8 111 0 86 0z"/></svg>
                        ) : schedule.project?.provider === 'azure' ? (
                          <svg viewBox="0 0 24 24" width="24" height="24"><path fill="#0078D4" d="M11.4 5.3l-8.5 13.4H12l2.6-4.1H7.8l5.2-8.3L11.4 5.3z M21.1 18.7l-9.7-15.4L8.8 7.4l6.4 11.3H21.1z"/></svg>
                        ) : (
                          <svg viewBox="0 0 24 24" width="24" height="24"><path fill="#4285F4" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13h2v6h-2zm0 8h2v2h-2z"/></svg>
                        )}
                      </div>
                    </div>

                    {/* Next Run / Last Run grid */}
                    <div style={{ 
                      background: 'var(--color-bg)', padding: '14px 16px', borderRadius: '10px', 
                      marginBottom: 'var(--spacing-4)', 
                      border: '1px solid var(--color-border)',
                      paddingLeft: '22px'
                    }}>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                        <div>
                          <div style={{ fontSize: '10px', color: 'var(--color-text-muted)', marginBottom: '6px', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
                            🕐 Next Run
                          </div>
                          <div style={{ fontSize: '13px', fontWeight: 700, color: nextRunStatus.color }}>
                            {nextRunStatus.label}
                          </div>
                          {schedule.isActive && (
                            <div style={{ fontSize: '11px', color: 'var(--color-text-muted)', marginTop: '2px' }}>
                              {formatDateTime(schedule.nextRun)}
                            </div>
                          )}
                        </div>
                        <div>
                          <div style={{ fontSize: '10px', color: 'var(--color-text-muted)', marginBottom: '6px', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
                            ✓ Last Run
                          </div>
                          <div style={{ fontSize: '13px', fontWeight: 600, color: schedule.lastRun ? 'var(--color-text)' : 'var(--color-text-muted)' }}>
                            {schedule.lastRun ? formatDateTime(schedule.lastRun) : 'Never'}
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Report email chip */}
                    {(schedule.targetEmail) && (
                      <div style={{ 
                        display: 'flex', alignItems: 'center', gap: '8px',
                        background: 'rgba(120, 120, 212, 0.07)',
                        border: '1px solid rgba(120, 120, 212, 0.15)',
                        borderRadius: '8px', padding: '8px 12px',
                        marginBottom: 'var(--spacing-4)',
                        paddingLeft: '20px'
                      }}>
                        <span style={{ fontSize: '13px' }}>📧</span>
                        <span style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>Report to:</span>
                        <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {schedule.targetEmail}
                        </span>
                      </div>
                    )}

                    <div style={{ display: 'flex', gap: 'var(--spacing-3)', paddingLeft: '8px' }}>
                      <button 
                        onClick={() => toggleSchedule(schedule.id)}
                        style={{ 
                          flex: 1, padding: '10px', borderRadius: '6px', 
                          background: schedule.isActive ? 'rgba(239,68,68,0.08)' : 'rgba(34,197,94,0.08)',
                          border: `1px solid ${schedule.isActive ? 'rgba(239,68,68,0.2)' : 'rgba(34,197,94,0.2)'}`,
                          color: schedule.isActive ? '#ef4444' : '#22c55e',
                          cursor: 'pointer', fontSize: '13px', fontWeight: 600
                        }}
                      >
                        {schedule.isActive ? 'Pause' : 'Resume'}
                      </button>
                      <button 
                        onClick={() => handleRunNow(schedule.id)}
                        disabled={runningIds.has(schedule.id)}
                        style={{ 
                          flex: 1, padding: '10px', borderRadius: '6px', 
                          background: 'rgba(120, 120, 212, 0.1)',
                          border: '1px solid rgba(120, 120, 212, 0.3)',
                          color: 'var(--color-primary)',
                          cursor: runningIds.has(schedule.id) ? 'not-allowed' : 'pointer', 
                          fontSize: '13px', fontWeight: 600,
                          display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px'
                        }}
                      >
                        {runningIds.has(schedule.id) ? (
                          <>
                            <span className="spinner-border spinner-border-sm" role="status" aria-hidden="true" style={{ width: '12px', height: '12px', border: '2px solid currentColor', borderRightColor: 'transparent', borderRadius: '50%', animation: 'spin 0.7s linear infinite' }}></span>
                            Running...
                          </>
                        ) : '⚡ Run Now'}
                      </button>
                      <button 
                        onClick={() => deleteSchedule(schedule.id)}
                        style={{ 
                          flex: 1, padding: '10px', borderRadius: '6px', 
                          background: 'transparent',
                          border: '1px solid var(--color-border)', 
                          color: 'var(--color-text-muted)', cursor: 'pointer', fontSize: '13px' 
                        }}
                      >
                        🗑 Remove
                      </button>
                    </div>
                  </Card>
                );
              })}
            </div>
          </>
        )}
      </div>

      <ScheduleModal 
        isOpen={isModalOpen}
        onClose={() => { setIsModalOpen(false); fetchData(true); }}
        projectId={selectedProject?.id}
        projectName={selectedProject?.name}
      />

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>
    </>
  );
};

export default AutomationPage;
