import React, { useState, useEffect } from 'react';
import AuthLayout from '../AuthLayout';
import Input from '../../../components/Input/Input';
import Button from '../../../components/Button/Button';
import styles from './ResetPasswordPage.module.css';
import toast from 'react-hot-toast';

const ResetPasswordPage = () => {
  const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' ? 'http://localhost:8000' : 'https://cloud-security-audit.onrender.com';

  const [otp,             setOtp]             = useState('');
  const [newPassword,     setNewPassword]     = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading,         setLoading]         = useState(false);
  const [done,            setDone]            = useState(false);
  const [showPw,          setShowPw]          = useState(false);

  const params = new URLSearchParams(window.location.search);
  const email  = params.get('email') || '';

  // If someone lands here without an email param, redirect
  useEffect(() => {
    if (!email) window.location.replace('/forgot-password');
  }, [email]);

  const handleResend = async () => {
    try {
      await fetch(`${API_BASE}/api/auth/forgot-password`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ email }),
      });
      toast.success('New reset code sent to your email!');
    } catch {
      toast.error('Could not resend. Please try again.');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (newPassword !== confirmPassword) {
      toast.error('Passwords do not match.');
      return;
    }
    if (newPassword.length < 6) {
      toast.error('Password must be at least 6 characters.');
      return;
    }

    setLoading(true);

    try {
      const res  = await fetch(`${API_BASE}/api/auth/reset-password`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ email, otp: otp.trim(), newPassword }),
      });
      const data = await res.json();

      if (!res.ok) throw new Error(data.error || 'Failed to reset password');

      setDone(true);
      toast.success('Password reset! Redirecting to login…', { duration: 3000 });
      setTimeout(() => { window.location.href = '/login'; }, 2500);

    } catch (err) {
      toast.error(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (!email) return null;

  return (
    <AuthLayout
      title="Reset Password"
      subtitle={`Enter the 6-digit code sent to ${email}`}
    >
      {done ? (
        <div style={{ textAlign: 'center', padding: '24px 0' }}>
          <div style={{ fontSize: '48px', marginBottom: '12px' }}>✅</div>
          <p style={{ color: 'var(--color-text-muted)', fontSize: '14px', lineHeight: 1.6 }}>
            Your password has been reset.<br />
            Redirecting to login…
          </p>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className={styles.form}>

          {/* OTP input — styled like a code box */}
          <div style={{ marginBottom: '16px' }}>
            <label style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-text)', marginBottom: '6px', display: 'block' }}>
              Reset Code
            </label>
            <input
              type="text"
              inputMode="numeric"
              maxLength={6}
              value={otp}
              onChange={(e) => setOtp(e.target.value.replace(/\D/g, ''))}
              placeholder="• • • • • •"
              required
              style={{
                width: '100%', padding: '12px 16px',
                fontSize: '22px', fontWeight: 700, letterSpacing: '12px', textAlign: 'center',
                border: '1.5px solid var(--color-border)', borderRadius: '10px',
                outline: 'none', background: 'var(--color-bg)',
                color: 'var(--color-text)', boxSizing: 'border-box',
                transition: 'border-color 0.2s',
              }}
              onFocus={(e)  => e.target.style.borderColor = '#4f46e5'}
              onBlur={(e)   => e.target.style.borderColor = 'var(--color-border)'}
            />
            <button
              type="button"
              onClick={handleResend}
              style={{ marginTop: '6px', background: 'none', border: 'none', color: '#4f46e5', cursor: 'pointer', fontSize: '12px', padding: 0 }}
            >
              Didn't receive it? Resend code
            </button>
          </div>

          {/* New password */}
          <div style={{ position: 'relative', marginBottom: '16px' }}>
            <Input
              label="New Password"
              type={showPw ? 'text' : 'password'}
              placeholder="Minimum 6 characters"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
            />
          </div>

          {/* Confirm password */}
          <Input
            label="Confirm New Password"
            type={showPw ? 'text' : 'password'}
            placeholder="Re-enter password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
          />

          {/* Show/hide toggle */}
          <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: 'var(--color-text-muted)', cursor: 'pointer', marginBottom: '8px', userSelect: 'none' }}>
            <input type="checkbox" checked={showPw} onChange={(e) => setShowPw(e.target.checked)} />
            Show passwords
          </label>

          {/* Password strength hint */}
          {newPassword.length > 0 && (
            <div style={{ marginBottom: '12px' }}>
              <div style={{ display: 'flex', gap: '4px', marginBottom: '4px' }}>
                {[1,2,3,4].map(i => (
                  <div key={i} style={{
                    flex: 1, height: '4px', borderRadius: '2px',
                    background: newPassword.length >= i * 3 ? (newPassword.length >= 10 ? '#22c55e' : newPassword.length >= 6 ? '#eab308' : '#ef4444') : 'var(--color-border)',
                    transition: 'background 0.3s',
                  }} />
                ))}
              </div>
              <span style={{ fontSize: '11px', color: newPassword.length >= 10 ? '#22c55e' : newPassword.length >= 6 ? '#eab308' : '#ef4444' }}>
                {newPassword.length < 6 ? 'Too weak' : newPassword.length < 10 ? 'Fair' : 'Strong'}
              </span>
            </div>
          )}

          <Button type="submit" variant="primary" className={styles.submitBtn} loading={loading}>
            Reset Password
          </Button>
        </form>
      )}

      <div className={styles.footerText || ''} style={{ textAlign: 'center', marginTop: '16px', fontSize: '13px' }}>
        <a href="/forgot-password" style={{ color: '#4f46e5', textDecoration: 'none' }}>
          ← Request a new code
        </a>
      </div>
    </AuthLayout>
  );
};

export default ResetPasswordPage;
