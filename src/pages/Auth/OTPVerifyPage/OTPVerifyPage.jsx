import React, { useState, useRef, useEffect, useContext } from 'react';
import { AuthContext } from '../../../contexts/AuthContext';
import AuthLayout from '../AuthLayout';
import Button from '../../../components/Button/Button';
import styles from './OTPVerifyPage.module.css';
import toast from 'react-hot-toast';

const OTPVerifyPage = () => {
  const { verifyOtp } = useContext(AuthContext);
  const [otp, setOtp] = useState(['', '', '', '', '', '']);
  const [isVerifying, setIsVerifying] = useState(false);
  const inputRefs = useRef([]);

  // Extract email and context from URL (basic vanilla approach)
  const urlParams = new URLSearchParams(window.location.search);
  const email = urlParams.get('email') || 'your email';
  const context = urlParams.get('context'); // 'reset' or undefined (registration)

  useEffect(() => {
    // Focus first input on mount
    if (inputRefs.current[0]) {
      inputRefs.current[0].focus();
    }
  }, []);

  const handleChange = (index, value) => {
    // Only allow numbers
    if (isNaN(value)) return;

    const newOtp = [...otp];
    // Allow pasting
    if (value.length > 1) {
      const pastedData = value.substring(0, 6).split('');
      for (let i = 0; i < pastedData.length; i++) {
        if (index + i < 6) newOtp[index + i] = pastedData[i];
      }
      setOtp(newOtp);
      // Focus the next empty input or the last one
      const nextEmptyIndex = newOtp.findIndex(val => val === '');
      const focusIndex = nextEmptyIndex === -1 ? 5 : nextEmptyIndex;
      inputRefs.current[focusIndex]?.focus();
      return;
    }

    newOtp[index] = value;
    setOtp(newOtp);

    // Auto-focus next input
    if (value !== '' && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handleKeyDown = (index, e) => {
    if (e.key === 'Backspace' && !otp[index] && index > 0) {
      // Auto-focus previous input on backspace if current is empty
      inputRefs.current[index - 1]?.focus();
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    const otpString = otp.join('');
    if (otpString.length < 6) return; 
    
    setIsVerifying(true);
    
    // Call real AuthContext method
    const verifyPromise = verifyOtp(email, otpString);

    toast.promise(verifyPromise, {
      loading: 'Verifying code...',
      success: (result) => {
        if (!result.success) throw new Error(result.error);
        return 'Successfully signed up! Redirecting to login...';
      },
      error: (err) => err.message
    }).then((result) => {
      if (result && result.success) {
        if (context === 'reset') {
          window.location.href = '/reset-password?email=' + encodeURIComponent(email);
        } else {
          // Changed to redirect to login
          setTimeout(() => {
            window.location.href = '/login';
          }, 2000);
        }
      }
    }).catch(() => {})
    .finally(() => setIsVerifying(false));
  };

  return (
    <AuthLayout 
      title="Verify Your Identity" 
      subtitle={`We've sent a 6-digit verification code to ${email}`}
    >
      <form onSubmit={handleSubmit} className={styles.form}>
        <div className={styles.otpContainer}>
          {otp.map((digit, i) => (
             <input
               key={i}
               ref={(el) => (inputRefs.current[i] = el)}
               type="text"
               inputMode="numeric"
               maxLength={6}
               value={digit}
               onChange={(e) => handleChange(i, e.target.value)}
               onKeyDown={(e) => handleKeyDown(i, e)}
               className={`${styles.otpInput} ${digit ? styles.filled : ''}`}
               disabled={isVerifying}
             />
          ))}
        </div>
        
        <Button 
          type="submit" 
          variant="primary" 
          className={styles.submitBtn}
          disabled={isVerifying || otp.join('').length < 6}
        >
          {isVerifying ? 'Verifying...' : 'Verify Code'}
        </Button>
      </form>

      <div className={styles.footerText}>
        Didn't receive the code? <button type="button" className={styles.linkButton} onClick={() => toast("Contact support or check spam folder.")}>Resend</button>
      </div>
    </AuthLayout>
  );
};

export default OTPVerifyPage;
