import React, { useState, useEffect } from 'react';

import Card from '../../components/Card/Card';

const ProjectsPage = () => {
  const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:8000'
    : (window.location.hostname.includes('run.app') 
        ? 'https://cloud-security-audit.onrender.com' 
        : 'https://cloud-security-audit.onrender.com');

  const [projects, setProjects] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchProjects = async () => {
      try {
        const token = localStorage.getItem('auditscope_token');
        const res = await fetch(`${API_BASE}/api/projects`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await res.json();
        
        if (!Array.isArray(data)) {
          console.error('Projects API did not return an array:', data);
          setProjects([]);
          return;
        }

        // Deduplicate locally by name to fix any old data issues
        const uniqueProjectsMap = new Map();
        data.forEach(p => {
          if (!uniqueProjectsMap.has(p.name)) {
            uniqueProjectsMap.set(p.name, p);
          } else {
            // Merge scan count for duplicates
            const curr = uniqueProjectsMap.get(p.name);
            curr._count = curr._count || { scans: 0 };
            const additional = p._count?.scans || 0;
            curr._count.scans += additional;
          }
        });
        
        setProjects(Array.from(uniqueProjectsMap.values()));
      } catch (err) {
        console.error('Failed to fetch projects:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchProjects();
  }, []);

  return (
    <>
      <div style={{ paddingBottom: 'var(--spacing-4)' }}>
        <h1 style={{ fontSize: 'var(--font-size-xl)', marginBottom: 'var(--spacing-1)' }}>Projects</h1>
        <p style={{ color: 'var(--color-text-muted)', fontSize: 'var(--font-size-sm)', marginBottom: 'var(--spacing-6)' }}>
          Cloud projects you have previously scanned.
        </p>

        {loading ? (
          <div style={{ textAlign: 'center', color: 'var(--color-text-muted)', padding: 'var(--spacing-8)' }}>Loading projects...</div>
        ) : projects.length === 0 ? (
          <Card style={{ minHeight: '200px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 'var(--spacing-3)' }}>
            <div style={{ fontSize: '2.5rem', opacity: 0.5 }}>📁</div>
            <h3 style={{ color: 'var(--color-text)' }}>No projects yet</h3>
            <p style={{ color: 'var(--color-text-muted)', fontSize: 'var(--font-size-sm)' }}>Run a scan to automatically create a project.</p>
          </Card>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 'var(--spacing-4)' }}>
            {projects.map((proj) => (
              <a key={proj.id} href={`/dashboard/projects/${proj.id}`} style={{ textDecoration: 'none' }}>
                <Card style={{ cursor: 'pointer', transition: 'transform 0.15s', padding: 'var(--spacing-4)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--spacing-3)' }}>
                    <span style={{ display: 'flex' }}>
                      {proj.provider === 'gcp' ? (
                        <svg viewBox="0 0 24 24" width="24" height="24"><path fill="#4285F4" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13h2v6h-2zm0 8h2v2h-2z"/></svg>
                      ) : proj.provider === 'aws' ? (
                        <svg viewBox="0 0 256 154" width="24" height="24"><path fill="#FF9900" d="M128 32c-34 0-61 17-61 46 0 18 10 32 29 39-4 3-5 5-5 8 0 4 3 6 8 6 10 0 22-9 33-19 16 10 36 15 54 15 36 0 61-17 61-46 0-14-6-26-17-34-14-11-36-16-59-16l-43 1z"/><path fill="#FF9900" d="M128 0c-45 0-82 25-82 56 0 20 16 38 41 48-12 13-33 24-58 29-5 1-4 3 1 3 45 0 86-21 106-53 23 10 49 16 77 16 45 0 82-25 82-56S259 0 214 0c-26 0-48 7-66 18C132 8 111 0 86 0z"/></svg>
                      ) : (
                        <svg viewBox="0 0 24 24" width="24" height="24"><path fill="#0078D4" d="M11.4 5.3l-8.5 13.4H12l2.6-4.1H7.8l5.2-8.3L11.4 5.3z M21.1 18.7l-9.7-15.4L8.8 7.4l6.4 11.3H21.1z"/></svg>
                      )}
                    </span>
                    <span style={{ fontSize: 'var(--font-size-xs)', padding: '2px 8px', borderRadius: '4px', backgroundColor: 'rgba(255,255,255,0.08)', color: 'var(--color-text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>
                      {proj.provider}
                    </span>
                  </div>
                  <h3 style={{ fontSize: 'var(--font-size-base)', marginBottom: 'var(--spacing-1)', color: 'var(--color-text)' }}>{proj.name}</h3>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)' }}>
                      {proj._count?.scans || 0} scan(s)
                    </span>
                    <span style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-text-muted)' }}>
                      {new Date(proj.createdAt).toLocaleDateString()}
                    </span>
                  </div>
                </Card>
              </a>
            ))}
          </div>
        )}
      </div>
    </>
  );
};

export default ProjectsPage;
