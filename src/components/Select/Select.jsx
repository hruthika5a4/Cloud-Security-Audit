import React from 'react';
import styles from './Select.module.css';

const Select = ({ 
  options = [], 
  value, 
  onChange, 
  placeholder = "Select...",
  className = '',
  id,
  ...props 
}) => {
  const generatedId = id || `select-${Math.random().toString(36).substr(2, 9)}`;

  return (
    <div className={`${styles.selectWrapper} ${className}`}>
      <select 
        id={generatedId}
        className={styles.select}
        value={value}
        onChange={onChange}
        {...props}
      >
        <option value="" disabled hidden>{placeholder}</option>
        {options.map((option, idx) => (
          <option key={idx} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      {/* Custom dropdown chevron icon */}
      <div className={styles.iconWrapper}>
        <svg width="12" height="8" viewBox="0 0 12 8" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M1 1.5L6 6.5L11 1.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
      </div>
    </div>
  );
};

export default Select;
