import React, { useState, useContext, useEffect } from 'react';
import { AuthContext } from '../../../contexts/AuthContext';
import AuthLayout from '../AuthLayout';
import Input from '../../../components/Input/Input';
import Button from '../../../components/Button/Button';
import styles from './LoginPage.module.css';
import toast from 'react-hot-toast';

const LoginPage = () => {
  const { login, user, loading } = useContext(AuthContext);
  const [email,    setEmail]    = useState('');
  const [password, setPassword] = useState('');
  const [busy,     setBusy]     = useState(false);

  // ── If already logged in → skip straight to dashboard ────────────
  useEffect(() => {
    if (!loading && user) {
      window.location.replace('/dashboard');
    }
  }, [user, loading]);

  // ── Show session-expired message (set by auto-logout) ────────────
  useEffect(() => {
    const reason = sessionStorage.getItem('logout_reason');
    if (reason) {
      sessionStorage.removeItem('logout_reason');
      // Small delay so the toast renders after the page mounts
      setTimeout(() => toast(reason, {
        icon: '⏰',
        duration: 5000,
        style: { background: '#1e293b', color: '#f1f5f9', fontSize: '13px' },
      }), 300);
    }
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setBusy(true);

    const loginPromise = login(email, password);

    toast.promise(loginPromise, {
      loading: 'Logging in...',
      success: (result) => {
        if (!result.success) throw new Error(result.error);
        return 'Logged in successfully!';
      },
      error: (err) => err.message,
    }).then((result) => {
      if (result && result.success) {
        window.location.href = '/dashboard';
      }
    }).catch((err) => {
      if (err.message && err.message.toLowerCase().includes('verify')) {
        setTimeout(() => {
          window.location.href = `/verify-otp?email=${encodeURIComponent(email)}`;
        }, 1500);
      }
    }).finally(() => setBusy(false));
  };

  // Don't render the form while we're still checking auth state
  // (avoids a flash of the login form before the redirect fires)
  if (loading || user) return null;

  return (
    <AuthLayout
      title="Welcome Back"
      subtitle="Enter your credentials to access your account"
    >
      <form onSubmit={handleSubmit} className={styles.form}>
        <Input
          label="Email Address"
          type="email"
          placeholder="name@company.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />

        <div className={styles.passwordGroup}>
          <Input
            label="Password"
            type="password"
            placeholder="••••••••"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <a href="/forgot-password" className={styles.forgotLink}>
            Forgot password?
          </a>
        </div>

        <Button type="submit" variant="primary" className={styles.submitBtn} loading={busy}>
          Log In
        </Button>
      </form>

      <div className={styles.footerText}>
        Don't have an account? <a href="/register" className={styles.link}>Sign up</a>
      </div>
    </AuthLayout>
  );
};

export default LoginPage;
