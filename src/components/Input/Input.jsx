import React, { useState } from 'react';
import { Eye, EyeOff } from 'lucide-react';
import styles from './Input.module.css';

const Input = React.forwardRef(({ 
  label, 
  error, 
  className = '', 
  id, 
  type = 'text',
  ...props 
}, ref) => {
  const [showPassword, setShowPassword] = useState(false);
  const generatedId = id || `input-${Math.random().toString(36).substr(2, 9)}`;

  const isPassword = type === 'password';
  const inputType = isPassword ? (showPassword ? 'text' : 'password') : type;

  return (
    <div className={`${styles.inputWrapper} ${className}`}>
      {label && (
        <label htmlFor={generatedId} className={styles.label}>
          {label}
        </label>
      )}
      <div className={styles.inputContainer}>
        <input
          ref={ref}
          id={generatedId}
          type={inputType}
          className={`${styles.input} ${error ? styles.inputError : ''} ${isPassword ? styles.inputWithIcon : ''}`}
          {...props}
        />
        {isPassword && (
          <button 
            type="button" 
            className={styles.eyeBtn} 
            onClick={() => setShowPassword(!showPassword)}
            tabIndex={-1}
            aria-label={showPassword ? "Hide password" : "Show password"}
          >
            {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
          </button>
        )}
      </div>
      {error && <span className={styles.errorMessage}>{error}</span>}
    </div>
  );
});

Input.displayName = 'Input';

export default Input;
