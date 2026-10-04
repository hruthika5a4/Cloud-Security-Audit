import React from 'react';
import styles from './Section.module.css';

const Section = ({ 
  children, 
  id, 
  title, 
  subtitle, 
  badge,
  className = '', 
  darker = false,
  ...props 
}) => {
  return (
    <section 
      id={id} 
      className={`${styles.section} ${darker ? styles.darker : ''} ${className}`} 
      {...props}
    >
      <div className={`container ${styles.container}`}>
        {(title || subtitle || badge) && (
          <div className={styles.header}>
            {badge && <span className={styles.badge}>{badge}</span>}
            {title && <h2 className={styles.title}>{title}</h2>}
            {subtitle && <p className={styles.subtitle}>{subtitle}</p>}
          </div>
        )}
        <div className={styles.content}>
          {children}
        </div>
      </div>
    </section>
  );
};

export default Section;
