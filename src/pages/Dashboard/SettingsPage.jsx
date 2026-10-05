import React, { useState, useEffect, useContext, useRef } from 'react';
import { AuthContext } from '../../contexts/AuthContext';
import styles from './SettingsPage.module.css';
import Button from '../../components/Button/Button';

const SettingsPage = () => {
    const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' ? 'http://localhost:8000' : 'https://cloud-security-audit.onrender.com';

    const { user, login } = useContext(AuthContext);

    const [name, setName] = useState('');
    const [displayPicture, setDisplayPicture] = useState(null);
    const [previewUrl, setPreviewUrl] = useState('');

    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const [successMsg, setSuccessMsg] = useState('');
    const [tourReset, setTourReset] = useState(false);

    const fileInputRef = useRef(null);

    const handleReplayTour = () => {
        localStorage.removeItem('auditscope_tour_done');
        setTourReset(true);
        setTimeout(() => {
            window.history.pushState(null, '', '/dashboard');
            window.dispatchEvent(new Event('popstate'));
        }, 400);
    };

    useEffect(() => {
        if (user) {
            setName(user.name || '');
            if (user.displayPicture) {
                if (user.displayPicture.startsWith('data:')) {
                    setPreviewUrl(user.displayPicture);
                } else {
                    setPreviewUrl(`${API_BASE}${user.displayPicture}`);
                }
            }
        }
    }, [user, API_BASE]);

    const handleFileChange = (e) => {
        const file = e.target.files[0];
        if (file) {
            setDisplayPicture(file);
            // Create a local preview URL
            const objectUrl = URL.createObjectURL(file);
            setPreviewUrl(objectUrl);

            // Free memory when component unmounts
            return () => URL.revokeObjectURL(objectUrl);
        }
    };

    const handleSaveContactInfo = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        setError('');
        setSuccessMsg('');

        try {
            const token = localStorage.getItem('auditscope_token');
            if (!token) throw new Error('You must be logged in to update your profile.');

            const formData = new FormData();
            if (name !== user?.name) {
                formData.append('name', name);
            }
            if (displayPicture) {
                formData.append('displayPicture', displayPicture);
            }

            // If nothing actually changed, dont make api call
            if (!formData.has('name') && !formData.has('displayPicture')) {
                setIsLoading(false);
                setSuccessMsg('No changes to save.');
                return;
            }

            const response = await fetch(`${API_BASE}/api/auth/profile`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                body: formData,
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Failed to update profile');
            }

            // Update local storage and context
            localStorage.setItem('auditscope_user', JSON.stringify(data));
            // Force reload to reflect changes globally easily (or implement updateUser in Context)
            window.location.reload();

            setSuccessMsg('Profile updated successfully!');
            setDisplayPicture(null); // Reset file input

        } catch (err) {
            setError(err.message);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className={styles.settingsPage}>
            <div className={styles.topNavigation}>
                <button className={styles.backBtn} onClick={() => window.history.back()}>
                    ← Back
                </button>
            </div>
            <header className={styles.header}>
                <h1 className={styles.title}>Settings</h1>
                <p className={styles.subtitle}>Manage your account preferences and personal information.</p>
            </header>

            <div className={styles.content}>
                <section className={styles.card}>
                    <div className={styles.cardHeader}>
                        <h2 className={styles.cardTitle}>Profile Information</h2>
                        <p className={styles.cardSubtitle}>Update your display picture and personal details.</p>
                    </div>

                    <form className={styles.form} onSubmit={handleSaveContactInfo}>

                        <div className={styles.profileSection}>
                            <div className={styles.avatarContainer}>
                                {previewUrl ? (
                                    <img src={previewUrl} alt="Profile Preview" className={styles.avatarImage} title="Click 'Change Picture' to update your avatar" />
                                ) : (
                                    <div className={styles.avatarPlaceholder}>
                                        {name ? name.charAt(0).toUpperCase() : 'U'}
                                    </div>
                                )}

                                <div className={styles.avatarActions}>
                                    <button
                                        type="button"
                                        className={styles.uploadBtn}
                                        onClick={() => fileInputRef.current?.click()}
                                    >
                                        Change Picture
                                    </button>
                                    <input
                                        type="file"
                                        ref={fileInputRef}
                                        onChange={handleFileChange}
                                        accept="image/jpeg, image/png, image/webp"
                                        className={styles.hiddenInput}
                                    />
                                    <p className={styles.uploadHint}>JPG, PNG or WebP. Max size of 5MB.</p>
                                </div>
                            </div>
                        </div>

                        <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 'var(--spacing-6)' }}>
                            <div className={styles.formGroup}>
                                <label htmlFor="name" className={styles.label}>Full Name</label>
                                <input
                                    id="name"
                                    type="text"
                                    value={name}
                                    onChange={(e) => setName(e.target.value)}
                                    className={styles.input}
                                    placeholder="Enter your full name"
                                />
                                <p className={styles.inputHint}>How your name will appear across the platform.</p>
                            </div>

                            <div className={styles.formGroup}>
                                <label htmlFor="email" className={styles.label}>Email Address</label>
                                <input
                                    id="email"
                                    type="email"
                                    value={user?.email || ''}
                                    disabled
                                    className={`${styles.input} ${styles.disabledInput}`}
                                    title="Email cannot be changed"
                                />
                                <p className={styles.inputHint}>Your verified email address for notifications.</p>
                            </div>
                        </div>

                        {error && <div className={styles.errorMessage}>{error}</div>}
                        {successMsg && <div className={styles.successMessage}>{successMsg}</div>}

                        <div className={styles.formActions}>
                            <Button type="submit" variant="primary" disabled={isLoading}>
                                {isLoading ? 'Saving Changes...' : 'Save Changes'}
                            </Button>
                        </div>

                    </form>
                </section>
            </div>

            {/* ── Product Tour card ── */}
            <div className={styles.content} style={{ marginTop: '24px' }}>
                <section className={styles.card}>
                    <div className={styles.cardHeader}>
                        <h2 className={styles.cardTitle}>🗺️ Product Tour</h2>
                        <p className={styles.cardSubtitle}>
                            Replay the interactive walkthrough that guides you through every feature of AuditScope.
                        </p>
                    </div>
                    <div style={{ padding: '8px 0 4px 0' }}>
                        <div style={{
                            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                            padding: '16px 20px', borderRadius: '10px',
                            background: 'rgba(139,92,246,0.06)',
                            border: '1px solid rgba(139,92,246,0.18)'
                        }}>
                            <div>
                                <div style={{ fontWeight: 600, fontSize: '14px', marginBottom: '4px' }}>
                                    Onboarding Walkthrough
                                </div>
                                <div style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}>
                                    {tourReset
                                        ? '✅ Tour reset! Taking you to the Dashboard...'
                                        : 'Click to replay the step-by-step tour on the Dashboard.'}
                                </div>
                            </div>
                            <button
                                onClick={handleReplayTour}
                                disabled={tourReset}
                                style={{
                                    padding: '10px 20px', borderRadius: '8px',
                                    background: tourReset
                                        ? 'rgba(34,197,94,0.15)'
                                        : 'linear-gradient(135deg, #8b5cf6, #6366f1)',
                                    border: 'none',
                                    color: tourReset ? '#22c55e' : '#fff',
                                    fontWeight: 700, fontSize: '13px',
                                    cursor: tourReset ? 'default' : 'pointer',
                                    boxShadow: tourReset ? 'none' : '0 4px 14px rgba(139,92,246,0.35)',
                                    whiteSpace: 'nowrap',
                                    transition: 'all 0.2s'
                                }}
                            >
                                {tourReset ? '✅ Done!' : '▶ Replay Tour'}
                            </button>
                        </div>
                    </div>
                </section>
            </div>
        </div>
    );
};

export default SettingsPage;
