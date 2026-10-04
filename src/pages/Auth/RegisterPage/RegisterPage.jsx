import React, { useState, useContext } from 'react';
import { AuthContext } from '../../../contexts/AuthContext';
import AuthLayout from '../AuthLayout';
import Input from '../../../components/Input/Input';
import Button from '../../../components/Button/Button';
import styles from './RegisterPage.module.css';
import toast from 'react-hot-toast';

const RegisterPage = () => {
  const { register } = useContext(AuthContext);
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    const toastId = toast.loading('Creating your account...');
    
    try {
      const result = await register(name, email, password);
      
      if (result.success) {
        toast.success('OTP sent to your email!', { id: toastId });
        window.location.href = `/verify-otp?email=${encodeURIComponent(result.email || email)}`;
      } else {
        toast.error(result.error || 'Failed to create account', { id: toastId });
      }
    } catch (err) {
      toast.error(err.message || 'An unexpected error occurred', { id: toastId });
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout 
      title="Create an Account" 
      subtitle="Join AuditScope to secure your cloud infrastructure"
    >
      <form onSubmit={handleSubmit} className={styles.form}>
        <Input 
          label="Full Name" 
          type="text" 
          placeholder="John Doe" 
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />

        <Input 
          label="Work Email" 
          type="email" 
          placeholder="name@company.com" 
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        
        <Input 
          label="Password" 
          type="password" 
          placeholder="Create a strong password" 
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        
        <Button type="submit" variant="primary" className={styles.submitBtn} disabled={loading}>
          Create Account
        </Button>
      </form>

      <div className={styles.termsText}>
        By signing up, you agree to our <a href="/">Terms of Service</a> and <a href="/">Privacy Policy</a>.
      </div>

      <div className={styles.footerText}>
        Already have an account? <a href="/login" className={styles.link}>Log in</a>
      </div>
    </AuthLayout>
  );
};

export default RegisterPage;
