import React, { useState } from 'react';
import AuthLayout from '../AuthLayout';
import Input from '../../../components/Input/Input';
import Button from '../../../components/Button/Button';
import styles from './ForgotPasswordPage.module.css';
import toast from 'react-hot-toast';

const ForgotPasswordPage = () => {
  const API_BASE = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
    ? 'http://localhost:8000'
    : 'https://security-audit-accelerator-backend-196053730058.asia-south1.run.app';

  const [email,    setEmail]    = useState('');
  const [loading,  setLoading]  = useState(false);
  const [sent,     setSent]     = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const res  = await fetch(`${API_BASE}/api/auth/forgot-password`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ email }),
      });
      const data = await res.json();

      if (!res.ok) throw new Error(data.error || 'Failed to send reset code');

      setSent(true);
      toast.success('Reset code sent! Check your email inbox.', { duration: 4000 });

      // Redirect to reset page after 1.5s
      setTimeout(() => {
        window.location.href = `/reset-password?email=${encodeURIComponent(email)}`;
      }, 1500);

    } catch (err) {
      toast.error(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout
      title="Forgot Password"
      subtitle={sent
        ? 'A 6-digit OTP has been sent to your email — redirecting…'
        : 'Enter your registered email and we\'ll send you a reset code'}
    >
      {!sent ? (
        <form onSubmit={handleSubmit} className={styles.form}>
          <Input
            label="Email Address"
            type="email"
            placeholder="name@company.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />

          <Button type="submit" variant="primary" className={styles.submitBtn} loading={loading}>
            Send Reset Code
          </Button>
        </form>
      ) : (
        /* Success state */
        <div style={{ textAlign: 'center', padding: '24px 0' }}>
          <div style={{ fontSize: '48px', marginBottom: '12px' }}>📬</div>
          <p style={{ color: 'var(--color-text-muted)', fontSize: '14px', lineHeight: 1.6 }}>
            We sent a 6-digit code to <strong>{email}</strong>.<br />
            Redirecting you to the reset page…
          </p>
        </div>
      )}

      <div className={styles.footerText}>
        <a href="/login" className={styles.link}>← Back to Log In</a>
      </div>
    </AuthLayout>
  );
};

export default ForgotPasswordPage;
