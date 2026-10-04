import React from 'react';
import styles from './Sidebar.module.css';

// Tour target IDs map each nav item to its data-tour value
const navItems = [
  { 
    name: 'Dashboard',   
    path: '/dashboard',            
    icon: <svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/></svg>, 
    tourId: 'tour-sidebar-dashboard'  
  },
  { 
    name: 'Projects',    
    path: '/dashboard/projects',   
    icon: <svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>, 
    tourId: 'tour-sidebar-projects'   
  },
  { 
    name: 'Automation',  
    path: '/dashboard/automation', 
    icon: <svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z"/></svg>, 
    tourId: 'tour-sidebar-automation' 
  },
  { 
    name: 'Scan History',
    path: '/dashboard/history',    
    icon: <svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M13 3c-4.97 0-9 4.03-9 9H1l3.89 3.89.07.14L9 12H6c0-3.87 3.13-7 7-7s7 3.13 7 7-3.13 7-7 7c-1.93 0-3.68-.79-4.94-2.06l-1.42 1.42C8.27 19.99 10.51 21 13 21c4.97 0 9-4.03 9-9s-4.03-9-9-9zm-1 5v5l4.28 2.54.72-1.21-3.5-2.08V8H12z"/></svg>, 
    tourId: 'tour-sidebar-history'    
  },
];

const Sidebar = ({ currentPath }) => {
  return (
    <aside className={styles.sidebar}>
      <div className={styles.sidebarHeader}>
        <a href="/" className={styles.logo}>
          <div className={styles.logoIcon}>A</div>
          <div className={styles.logoText}>
            <span className={styles.logoMain}>Audit</span>
            <span className={styles.logoSub}>Scope</span>
          </div>
        </a>
      </div>

      <nav className={styles.navContainer}>
        <ul className={styles.navList}>
          {navItems.map((item, index) => {
            const isActive =
              currentPath === item.path ||
              (currentPath.startsWith(item.path) && item.path !== '/dashboard');

            return (
              <li key={index} className={styles.navItem}>
                <a
                  href={item.path}
                  data-tour={item.tourId}
                  className={`${styles.navLink} ${isActive ? styles.active : ''}`}
                >
                  <span className={styles.icon}>{item.icon}</span>
                  <span className={styles.linkText}>{item.name}</span>
                </a>
              </li>
            );
          })}
        </ul>
      </nav>

      <div className={styles.sidebarFooter}>
        <a
          href="/dashboard/settings"
          data-tour="tour-sidebar-settings"
          className={`${styles.navLink} ${currentPath.includes('/settings') ? styles.active : ''}`}
        >
          <span className={styles.icon}><svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/></svg></span>
          <span className={styles.linkText}>Settings</span>
        </a>
      </div>
    </aside>
  );
};

export default Sidebar;
