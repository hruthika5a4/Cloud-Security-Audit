import React from 'react';
import { Loader2 } from 'lucide-react';
import styles from './Button.module.css';

const Button = ({ 
  children, 
  variant = 'primary', 
  size = 'medium', 
  className = '', 
  loading = false,
  disabled = false,
  onClick, 
  ...props 
}) => {
  const buttonClass = `${styles.button} ${styles[variant]} ${styles[size]} ${className} ${loading ? styles.loadingState : ''}`;
  
  return (
    <button 
      className={buttonClass} 
      onClick={onClick} 
      disabled={disabled || loading}
      {...props}
    >
      {loading && <Loader2 className={styles.spinner} size={18} />}
      <span className={`${styles.contentContainer} ${loading ? styles.hiddenText : ''}`}>{children}</span>
    </button>
  );
};

export default Button;
