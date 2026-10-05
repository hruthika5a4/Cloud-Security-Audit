import React, { createContext, useState, useEffect, useRef } from 'react';

export const AuthContext = createContext();

const SESSION_DURATION = 6 * 60 * 60 * 1000; // 6 hours in ms

const clearSession = () => {
  localStorage.removeItem('auditscope_token');
  localStorage.removeItem('auditscope_user');
  localStorage.removeItem('auditscope_login_time');
  localStorage.removeItem('last_viewed_scan');
  localStorage.removeItem('latest_scan_result');
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const autoLogoutTimer = useRef(null);

  // Schedule auto-logout at exactly the 6-hour mark
  const scheduleAutoLogout = (loginTime) => {
    if (autoLogoutTimer.current) clearTimeout(autoLogoutTimer.current);
    const remaining = SESSION_DURATION - (Date.now() - loginTime);
    if (remaining <= 0) {
      performLogout(true);
      return;
    }
    autoLogoutTimer.current = setTimeout(() => {
      performLogout(true);
    }, remaining);
  };

  const performLogout = (auto = false) => {
    if (autoLogoutTimer.current) clearTimeout(autoLogoutTimer.current);
    clearSession();
    setUser(null);
    if (auto) {
      // Show a message and redirect to landing page
      sessionStorage.setItem('logout_reason', 'Your session expired after 6 hours. Please log in again.');
    }
    window.location.replace('/');
  };

  // Check auth state — called on mount, pageshow, and storage events
  const checkAuth = () => {
    const token     = localStorage.getItem('auditscope_token');
    const savedUser = localStorage.getItem('auditscope_user');
    const loginTime = parseInt(localStorage.getItem('auditscope_login_time') || '0', 10);

    if (token && savedUser) {
      try {
        const payload   = JSON.parse(atob(token.split('.')[1]));
        const jwtExp    = payload.exp * 1000;
        const sessionExp = loginTime ? loginTime + SESSION_DURATION : 0;

        // Expired if JWT expired OR 6-hour session window passed
        const expired = jwtExp < Date.now() || (sessionExp && Date.now() > sessionExp);

        if (expired) {
          clearSession();
          setUser(null);
        } else {
          setUser(JSON.parse(savedUser));
          // Re-arm the auto-logout timer to fire at the 6-hour mark
          if (loginTime) scheduleAutoLogout(loginTime);
        }
      } catch {
        clearSession();
        setUser(null);
      }
    } else {
      setUser(null);
    }

    setLoading(false);
  };

  useEffect(() => {
    checkAuth();

    // BFcache: recheck if user hits Back after logout
    const onPageShow = (e) => { if (e.persisted) checkAuth(); };
    // Sync login/logout across tabs
    const onStorage  = () => checkAuth();

    window.addEventListener('pageshow', onPageShow);
    window.addEventListener('storage',  onStorage);

    return () => {
      window.removeEventListener('pageshow', onPageShow);
      window.removeEventListener('storage',  onStorage);
      if (autoLogoutTimer.current) clearTimeout(autoLogoutTimer.current);
    };
  }, []);

  // ── login ────────────────────────────────────────────────────────
  const login = async (email, password) => {
    try {
      const API_BASE = window.location.hostname.includes('run.app') 
        ? 'https://cloud-security-audit.onrender.com' 
        : 'http://localhost:8000';
      const response = await fetch(`${API_BASE}/api/auth/login`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ email, password })
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Login failed');

      const now = Date.now();
      localStorage.setItem('auditscope_token',      data.token);
      localStorage.setItem('auditscope_user',        JSON.stringify(data.user));
      localStorage.setItem('auditscope_login_time',  String(now));   // ← 6-hour clock starts here

      setUser(data.user);
      scheduleAutoLogout(now);
      return { success: true };
    } catch (err) {
      return { success: false, error: err.message };
    }
  };

  // ── register ─────────────────────────────────────────────────────
  const register = async (name, email, password) => {
    try {
      const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? 'http://localhost:8000'
        : (window.location.hostname.includes('run.app') 
            ? 'https://cloud-security-audit.onrender.com' 
            : 'https://cloud-security-audit.onrender.com');
      const response = await fetch(`${API_BASE}/api/auth/register`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ name, email, password })
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Registration failed');

      return { success: true, email: data.email };
    } catch (err) {
      return { success: false, error: err.message };
    }
  };

  // ── verifyOtp ─────────────────────────────────────────────────────
  const verifyOtp = async (email, otp) => {
    try {
      const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? 'http://localhost:8000'
        : (window.location.hostname.includes('run.app') 
            ? 'https://cloud-security-audit.onrender.com' 
            : 'https://cloud-security-audit.onrender.com');
      const response = await fetch(`${API_BASE}/api/auth/verify-otp`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ email, otp })
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Verification failed');

      const now = Date.now();
      localStorage.setItem('auditscope_token',      data.token);
      localStorage.setItem('auditscope_user',        JSON.stringify(data.user));
      localStorage.setItem('auditscope_login_time',  String(now));   // ← 6-hour clock starts here too

      setUser(data.user);
      scheduleAutoLogout(now);
      return { success: true };
    } catch (err) {
      return { success: false, error: err.message };
    }
  };

  // ── logout (manual) ───────────────────────────────────────────────
  const logout = () => performLogout(false);

  return (
    <AuthContext.Provider value={{ user, loading, login, register, verifyOtp, logout }}>
      {children}
    </AuthContext.Provider>
  );
};
