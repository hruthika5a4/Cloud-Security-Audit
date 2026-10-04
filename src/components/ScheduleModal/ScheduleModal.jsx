import React, { useState, useEffect } from 'react';
import Card from '../Card/Card';
import Button from '../Button/Button';

const ScheduleModal = ({ isOpen, onClose, projectId: initialProjectId, projectName: initialProjectName }) => {
    const [step, setStep] = useState(1);
    const [provider, setProvider] = useState('gcp');
    const [creds, setCreds] = useState('');
    const [frequency, setFrequency] = useState('daily');
    const [time, setTime] = useState('09:00');
    const [daysOfWeek, setDaysOfWeek] = useState(['Monday']);
    const [dayOfMonth, setDayOfMonth] = useState(1);
    const [targetEmails, setTargetEmails] = useState([]);
    const [emailInputValue, setEmailInputValue] = useState('');
    const [submitting, setSubmitting] = useState(false);
    const [success, setSuccess] = useState(false);

    const PROVIDER_META = {
        gcp:   { label: 'Google Cloud',       color: '#4285F4', bg: 'rgba(66,133,244,0.10)',   icon: <svg viewBox="0 0 24 24" width="22" height="22"><path fill="#EA4335" d="M12 24a11.94 11.94 0 0 1-8.48-3.52l3.41-3.41c1.35.85 2.96 1.35 4.7 1.35 4.3 0 7.84-3.54 7.84-7.84S15.93 2.74 11.63 2.74a7.84 7.84 0 0 0-7.84 7.84c0 1.63.5 3.12 1.35 4.37h.37l-4.7 4.7C.32 17.5 0 14.85 0 12 0 5.37 5.37 0 12 0s12 5.37 12 12-5.37 12-12 12z"/><path fill="#4285F4" d="M2.26 18.25L7 13.51a7.84 7.84 0 0 1-3.21-2.93l-4.7 4.7c.92 1.15 1.95 2.18 3.17 2.97z"/><path fill="#34A853" d="M12 21.26c-1.74 0-3.35-.5-4.7-1.35l-3.41 3.41a11.94 11.94 0 0 0 8.11 3.31V21.26z"/></svg> },
        aws:   { label: 'AWS',                color: '#FF9900', bg: 'rgba(255,153,0,0.10)',    icon: <svg viewBox="0 0 256 154" width="22" height="22"><path fill="#232F3E" d="M128 32c-34 0-61 17-61 46 0 18 10 32 29 39-4 3-5 5-5 8 0 4 3 6 8 6 10 0 22-9 33-19 16 10 36 15 54 15 36 0 61-17 61-46 0-14-6-26-17-34-14-11-36-16-59-16l-43 1z"/><path fill="#FF9900" d="M128 0c-45 0-82 25-82 56 0 20 16 38 41 48-12 13-33 24-58 29-5 1-4 3 1 3 45 0 86-21 106-53 23 10 49 16 77 16 45 0 82-25 82-56S259 0 214 0c-26 0-48 7-66 18C132 8 111 0 86 0z"/></svg> },
        azure: { label: 'Azure',              color: '#0078D4', bg: 'rgba(0,120,212,0.10)',    icon: <svg viewBox="0 0 24 24" width="22" height="22"><path fill="#0072C6" d="M11.4 5.3l-8.5 13.4H12l2.6-4.1H7.8l5.2-8.3L11.4 5.3z M21.1 18.7l-9.7-15.4L8.8 7.4l6.4 11.3H21.1z"/></svg> },
    };

    const days = [
        { id: 'Monday', label: 'Mon' },
        { id: 'Tuesday', label: 'Tue' },
        { id: 'Wednesday', label: 'Wed' },
        { id: 'Thursday', label: 'Thu' },
        { id: 'Friday', label: 'Fri' },
        { id: 'Saturday', label: 'Sat' },
        { id: 'Sunday', label: 'Sun' }
    ];

    // Pre-fill email from logged-in user profile
    useEffect(() => {
        if (isOpen) {
            try {
                const userStr = localStorage.getItem('auditscope_user');
                if (userStr) {
                    const user = JSON.parse(userStr);
                    if (user.email && targetEmails.length === 0) {
                        setTargetEmails([user.email]);
                    }
                }
            } catch (e) {}
        }
    }, [isOpen]);

    const addEmail = () => {
        const email = emailInputValue.trim();
        if (email && email.includes('@') && !targetEmails.includes(email)) {
            setTargetEmails([...targetEmails, email]);
            setEmailInputValue('');
        }
    };

    const removeEmail = (email) => {
        setTargetEmails(targetEmails.filter(e => e !== email));
    };

    if (!isOpen) return null;

    const toggleDay = (day) => {
        if (daysOfWeek.includes(day)) {
            setDaysOfWeek(daysOfWeek.filter(d => d !== day));
        } else {
            setDaysOfWeek([...daysOfWeek, day]);
        }
    };

    const renderTimePicker = () => {
        const [h, m] = time.split(':');
        let hour24 = parseInt(h);
        const ampm = hour24 >= 12 ? 'PM' : 'AM';
        let hour12 = hour24 % 12 || 12;

        const updateTime = (newHour12, newMinute, newAmPm) => {
            let h24 = parseInt(newHour12) || 12;
            let mInt = parseInt(newMinute) || 0;
            
            if (newAmPm === 'PM' && h24 < 12) h24 += 12;
            if (newAmPm === 'AM' && h24 === 12) h24 = 0;
            
            const finalTime = `${h24.toString().padStart(2, '0')}:${mInt.toString().padStart(2, '0')}`;
            setTime(finalTime);
        };
        
        const inputStyle = {
            padding: '10px 8px', background: 'var(--color-bg-secondary)', color: 'var(--color-text)', 
            border: '1px solid var(--color-border)', borderRadius: '6px', outline: 'none', 
            fontSize: '1.2rem', textAlign: 'center', width: '65px', fontWeight: 600, fontFamily: 'monospace'
        };

        return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <div style={{ fontSize: '11px', color: 'var(--color-primary)', fontWeight: 600, background: 'rgba(120, 120, 212, 0.1)', padding: '6px 10px', borderRadius: '4px', borderLeft: '2px solid var(--color-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span>⏱️</span> 12-hour clock (IST) format actively applied.
                </div>
                
                <div style={{ display: 'flex', gap: '10px', alignItems: 'center', background: 'var(--color-bg)', padding: '12px', borderRadius: '8px', border: '1px solid var(--color-border)' }}>
                    <input 
                        type="number" 
                        min="1" max="12" 
                        value={hour12} 
                        onChange={e => updateTime(e.target.value, m, ampm)}
                        onBlur={e => {
                            let val = parseInt(e.target.value);
                            if (isNaN(val) || val < 1) val = 1;
                            if (val > 12) val = 12;
                            updateTime(val, m, ampm);
                        }}
                        style={inputStyle}
                        title="Hour (1-12)"
                    />
                    <span style={{ fontSize: '1.6rem', color: 'var(--color-text-muted)', fontWeight: 800 }}>:</span>
                    <input 
                        type="number" 
                        min="0" max="59" step="15"
                        value={m} 
                        onChange={e => updateTime(hour12, e.target.value, ampm)}
                        onBlur={e => {
                            let val = parseInt(e.target.value);
                            if (isNaN(val) || val < 0) val = 0;
                            if (val > 59) val = 59;
                            updateTime(hour12, val, ampm);
                        }}
                        style={inputStyle}
                        title="Minute (0-59)"
                    />
                    <div style={{ width: '8px', flex: 1 }}></div>
                    <select 
                        value={ampm} 
                        onChange={e => updateTime(hour12, m, e.target.value)}
                        style={{ padding: '10px 14px', background: 'rgba(120, 120, 212, 0.15)', color: 'var(--color-primary)', fontWeight: 800, border: '1px solid rgba(120, 120, 212, 0.3)', borderRadius: '6px', outline: 'none', fontSize: '1.1rem', cursor: 'pointer', textAlign: 'center' }}
                    >
                        <option value="AM" style={{ background: 'var(--color-bg)', color: 'var(--color-text)' }}>AM</option>
                        <option value="PM" style={{ background: 'var(--color-bg)', color: 'var(--color-text)' }}>PM</option>
                    </select>
                </div>
            </div>
        );
    };

    const handleSave = async (e) => {
        e.preventDefault();
        if (targetEmails.length === 0) {
            alert('Please add at least one recipient email address.');
            return;
        }
        setSubmitting(true);
        try {
            // Frontend Timezone Spoofing algorithm mapping target time cleanly onto UTC
            const d = new Date();
            const [localHours, localMinutes] = time.split(':').map(Number);
            d.setHours(localHours, localMinutes, 0, 0);
            
            let localDay = d.getDay();
            let utcDay = d.getUTCDay();
            
            let dayShift = utcDay - localDay;
            if (dayShift === -6) dayShift = 1;
            if (dayShift === 6) dayShift = -1;
            
            const spoofedTime = `${d.getUTCHours().toString().padStart(2, '0')}:${d.getUTCMinutes().toString().padStart(2, '0')}`;
            
            const allDays = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
            const spoofedDaysOfWeek = daysOfWeek.map(dayStr => {
                let idx = allDays.indexOf(dayStr);
                let shiftedIdx = (idx + dayShift + 7) % 7;
                return allDays[shiftedIdx];
            });

            let spoofedDayOfMonth = dayOfMonth;
            if (spoofedDayOfMonth) {
                spoofedDayOfMonth += dayShift;
                if (spoofedDayOfMonth <= 0) spoofedDayOfMonth = 0; // Triggers end-of-previous-month logic natively in UTC
            }

            const API_BASE = window.location.hostname.includes('run.app')
                ? 'https://security-audit-accelerator-backend-196053730058.asia-south1.run.app' 
                : 'http://localhost:8000';

            const token = localStorage.getItem('auditscope_token');
            const res = await fetch(`${API_BASE}/api/schedules`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    projectId: initialProjectId,
                    provider,
                    credentials: typeof creds === 'object' ? JSON.stringify(creds) : creds,
                    frequency,
                    time: spoofedTime,
                    daysOfWeek: spoofedDaysOfWeek,
                    dayOfMonth: spoofedDayOfMonth,
                    targetEmail: targetEmails.join(', ')
                })
            });

            if (res.ok) {
                setSuccess(true);
                setTimeout(() => {
                    setSuccess(false);
                    onClose();
                    setStep(1); // Reset
                    setTargetEmails([]);
                }, 2000);
            } else {
                const errData = await res.json();
                alert(`Failed to save schedule: ${errData.error || 'Unknown error'}`);
            }
        } catch (err) {
            console.error('Failed to save schedule', err);
            alert('Network error. Please check your connection and try again.');
        } finally {
            setSubmitting(false);
        }
    };

    const renderFrequencyContent = () => {
        switch (frequency) {
            case 'daily':
                return (
                    <div style={{ animation: 'fadeIn 0.3s' }}>
                        <p style={{ color: 'var(--color-text-muted)', fontSize: '13px', marginBottom: '12px' }}>Runs every single day at the specified time.</p>
                        {renderTimePicker()}
                    </div>
                );
            case 'weekly':
                return (
                    <div style={{ animation: 'fadeIn 0.3s' }}>
                        <p style={{ color: 'var(--color-text-muted)', fontSize: '13px', marginBottom: '12px' }}>Choose which days of the week to run the audit.</p>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '16px' }}>
                            {days.map(d => (
                                <div 
                                    key={d.id} 
                                    onClick={() => toggleDay(d.id)}
                                    style={{
                                        width: '45px', height: '45px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                                        background: daysOfWeek.includes(d.id) ? 'var(--color-primary)' : 'var(--color-bg)',
                                        color: daysOfWeek.includes(d.id) ? '#000' : 'var(--color-text)', cursor: 'pointer', transition: 'all 0.2s', fontWeight: 600, fontSize: '12px'
                                    }}
                                >
                                    {d.label}
                                </div>
                            ))}
                        </div>
                        {renderTimePicker()}
                    </div>
                );
            case 'monthly':
                return (
                    <div style={{ animation: 'fadeIn 0.3s' }}>
                        <p style={{ color: 'var(--color-text-muted)', fontSize: '13px', marginBottom: '12px' }}>Specify the day of the month (1-31).</p>
                        <div style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
                            <div style={{ flex: 1 }}>
                                <label style={{ display: 'block', fontSize: '11px', color: 'var(--color-text-muted)', marginBottom: '4px' }}>Day of Month</label>
                                <input 
                                    type="number" 
                                    min="1" max="31" 
                                    value={dayOfMonth} 
                                    onChange={(e) => setDayOfMonth(parseInt(e.target.value))}
                                    style={{ width: '100%', padding: '10px', background: 'var(--color-bg)', border: '1px solid var(--color-border)', borderRadius: '8px', color: 'var(--color-text)' }}
                                />
                            </div>
                            <div style={{ flex: 1 }}>
                                <label style={{ display: 'block', fontSize: '11px', color: 'var(--color-text-muted)', marginBottom: '4px' }}>Time</label>
                                {renderTimePicker()}
                            </div>
                        </div>
                    </div>
                );
            default: return null;
        }
    }

    return (
        <div style={{
            position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
            backgroundColor: 'rgba(0,0,0,0.4)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 5000,
            backdropFilter: 'blur(12px)'
        }}>
            <div style={{ width: '100%', maxWidth: '550px', position: 'relative' }} onClick={e => e.stopPropagation()}>
                <Card style={{ padding: 'var(--spacing-8)', position: 'relative', overflow: 'hidden', border: '1px solid var(--color-border)', background: 'var(--color-bg-secondary)', boxShadow: 'var(--shadow-2xl)' }}>
                    <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: '4px', background: 'linear-gradient(90deg, var(--color-primary), #a855f7)' }}></div>
                    
                    <button onClick={onClose} style={{ position: 'absolute', top: '24px', right: '24px', background: 'transparent', border: 'none', color: 'var(--color-text-muted)', cursor: 'pointer', fontSize: '18px' }}>✕</button>

                    <div style={{ display: 'flex', gap: '8px', marginBottom: '24px' }}>
                        {[1, 2, 3].map(s => (
                            <div key={s} style={{ height: '4px', flex: 1, borderRadius: '4px', background: step >= s ? 'var(--color-primary)' : 'var(--color-border)' }}></div>
                        ))}
                    </div>

                    <div style={{ textAlign: 'center', marginBottom: 'var(--spacing-8)' }}>
                        <h2 style={{ fontSize: 'var(--font-size-2xl)', marginBottom: 'var(--spacing-1)' }}>
                            {step === 1 ? 'Select Provider' : step === 2 ? 'Cloud Credentials' : 'Set Schedule'}
                        </h2>
                        <p style={{ color: 'var(--color-text-muted)', fontSize: 'var(--font-size-sm)' }}>
                            {step === 1 ? 'Which cloud ecosystem are we securing today?' : 
                             step === 2 ? 'Paste your Access Keys or Service Account JSON' : 
                             'When should we run the audit and where to send the report?'}
                        </p>
                    </div>

                    {success ? (
                        <div style={{ textAlign: 'center', color: 'var(--color-success)', padding: 'var(--spacing-8)', animation: 'scaleUp 0.4s' }}>
                            <div style={{ fontSize: '4rem', marginBottom: '1rem' }}>🏆</div>
                            <h3 style={{ margin: 0 }}>Automation Configured!</h3>
                            <p style={{ color: 'var(--color-text-muted)', marginTop: '8px' }}>
                                Reports will be delivered to <strong style={{ color: 'var(--color-primary)' }}>{targetEmails.length} recipient(s)</strong> at {time} on your schedule.
                            </p>
                        </div>
                    ) : (
                        <div>
                            {step === 1 && (
                                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '16px' }}>
                                    {[
                                        { id: 'gcp', label: 'GCP', icon: <svg viewBox="0 0 24 24" width="36" height="36"><path fill="#4285F4" d="M12 2L4.5 20.29l.71.71L12 18l6.79 3 .71-.71L12 2z"/></svg> },
                                        { id: 'aws', label: 'AWS', icon: <svg viewBox="0 0 256 154" width="36" height="36"><path fill="#FF9900" d="M128 32c-34 0-61 17-61 46 0 18 10 32 29 39-4 3-5 5-5 8 0 4 3 6 8 6 10 0 22-9 33-19 16 10 36 15 54 15 36 0 61-17 61-46 0-14-6-26-17-34-14-11-36-16-59-16l-43 1z"/></svg> },
                                        { id: 'azure', label: 'AZURE', icon: <svg viewBox="0 0 24 24" width="36" height="36"><path fill="#0078D4" d="M11.4 5.3l-8.5 13.4H12l2.6-4.1H7.8l5.2-8.3L11.4 5.3z M21.1 18.7l-9.7-15.4L8.8 7.4l6.4 11.3H21.1z"/></svg> }
                                    ].map(p => (
                                        <div 
                                            key={p.id} 
                                            onClick={() => { setProvider(p.id); setStep(2); }}
                                            style={{
                                                padding: '24px 16px', borderRadius: '16px', border: provider === p.id ? `2px solid var(--color-primary)` : '1px solid rgba(255,255,255,0.05)',
                                                background: provider === p.id ? 'rgba(var(--color-primary-rgb, 0, 120, 212), 0.1)' : 'var(--color-bg)', cursor: 'pointer', textAlign: 'center', transition: 'all 0.3s',
                                                display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px'
                                            }}
                                        >
                                            <div style={{ filter: provider === p.id ? 'none' : 'grayscale(1) opacity(0.6)' }}>{p.icon}</div>
                                            <div style={{ fontWeight: 800, fontSize: '11px', color: provider === p.id ? 'var(--color-primary)' : 'var(--color-text-muted)', letterSpacing: '0.05em' }}>{p.label}</div>
                                        </div>
                                    ))}
                                </div>
                            )}

                            {step === 2 && (
                                <div style={{ animation: 'slideIn 0.3s' }}>
                                    {provider === 'gcp' ? (
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                                            <div 
                                                onDragOver={(e) => e.preventDefault()}
                                                onDrop={(e) => {
                                                    e.preventDefault();
                                                    const file = e.dataTransfer.files[0];
                                                    if (file) {
                                                        const reader = new FileReader();
                                                        reader.onload = (re) => setCreds(re.target.result);
                                                        reader.readAsText(file);
                                                    }
                                                }}
                                                style={{ border: '2px dashed var(--color-border)', borderRadius: '12px', padding: '30px', textAlign: 'center', background: 'var(--color-bg)', cursor: 'pointer', transition: 'all 0.3s' }}
                                                onClick={() => {
                                                    const input = document.createElement('input');
                                                    input.type = 'file';
                                                    input.accept = '.json';
                                                    input.onchange = (e) => {
                                                        const file = e.target.files[0];
                                                        if (file) {
                                                            const reader = new FileReader();
                                                            reader.onload = (re) => setCreds(re.target.result);
                                                            reader.readAsText(file);
                                                        }
                                                    };
                                                    input.click();
                                                }}
                                            >
                                                <div style={{ fontSize: '2rem', marginBottom: '8px' }}>📄</div>
                                                <div style={{ fontWeight: 600, color: creds ? 'var(--color-success)' : 'var(--color-text)' }}>
                                                    {creds ? '✓ JSON Loaded' : 'Drop Service Account JSON'}
                                                </div>
                                                <div style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
                                                    {creds ? 'Click to replace file' : 'or click to browse...'}
                                                </div>
                                            </div>
                                            
                                            <div style={{ position: 'relative' }}>
                                                <div style={{ fontSize: '10px', color: 'var(--color-text-muted)', marginBottom: '8px', textAlign: 'center' }}>- OR PASTE MANUALLY -</div>
                                                <textarea 
                                                    placeholder="Paste Service Account JSON content here..."
                                                    value={creds && typeof creds === 'string' ? creds : ''}
                                                    onChange={(e) => setCreds(e.target.value)}
                                                    style={{ width: '100%', height: '120px', padding: '16px', background: 'var(--color-bg)', color: 'var(--color-text)', border: '1px solid var(--color-border)', borderRadius: '12px', fontFamily: 'monospace', fontSize: '13px', outline: 'none' }}
                                                />
                                            </div>
                                        </div>
                                    ) : (
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                                            <p style={{ color: 'var(--color-text-muted)', fontSize: '13px', marginTop: '-10px' }}>Provide your AWS IAM User credentials to authorize the read-only security audit.</p>
                                            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                                <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-text-muted)' }}>ACCESS KEY ID</label>
                                                <input 
                                                    type="text"
                                                    placeholder="AKIA..."
                                                    value={typeof creds === 'object' ? creds.accessKeyId : ''}
                                                    onChange={(e) => setCreds(prev => ({ ...(typeof prev === 'object' ? prev : {}), accessKeyId: e.target.value }))}
                                                    style={{ width: '100%', padding: '14px', background: 'var(--color-bg)', border: '1px solid var(--color-border)', borderRadius: '10px', color: 'var(--color-text)', outline: 'none' }}
                                                />
                                            </div>
                                            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                                <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-text-muted)' }}>SECRET ACCESS KEY</label>
                                                <input 
                                                    type="password"
                                                    placeholder="wJal..."
                                                    value={typeof creds === 'object' ? creds.secretAccessKey : ''}
                                                    onChange={(e) => setCreds(prev => ({ ...(typeof prev === 'object' ? prev : {}), secretAccessKey: e.target.value }))}
                                                    style={{ width: '100%', padding: '14px', background: 'var(--color-bg)', border: '1px solid var(--color-border)', borderRadius: '10px', color: 'var(--color-text)', outline: 'none' }}
                                                />
                                            </div>
                                        </div>
                                    )}
                                    <div style={{ display: 'flex', gap: '12px', marginTop: '24px' }}>
                                        <button onClick={() => setStep(1)} style={{ flex: 1, padding: '12px', borderRadius: '8px', background: 'transparent', border: '1px solid var(--color-border)', color: 'var(--color-text)', cursor: 'pointer' }}>Back</button>
                                        <button 
                                            onClick={() => setStep(3)} 
                                            disabled={!creds} 
                                            style={{ flex: 2, padding: '12px', borderRadius: '8px', background: 'var(--color-primary)', border: 'none', color: '#000', fontWeight: 700, cursor: 'pointer', boxShadow: 'var(--shadow-md)', opacity: creds ? 1 : 0.5 }}
                                        >
                                            Next: Configure Schedule
                                        </button>
                                    </div>
                                </div>
                            )}

                            {step === 3 && (
                                <div style={{ animation: 'slideIn 0.3s' }}>
                                    <div style={{ display: 'flex', gap: '8px', marginBottom: '20px' }}>
                                        {['daily', 'weekly', 'monthly'].map(f => (
                                            <div 
                                                key={f} 
                                                onClick={() => setFrequency(f)}
                                                style={{ flex: 1, padding: '10px', borderRadius: '8px', textAlign: 'center', background: frequency === f ? 'var(--color-primary)' : 'var(--color-bg)', color: frequency === f ? '#000' : 'var(--color-text-muted)', fontWeight: 600, cursor: 'pointer', textTransform: 'capitalize', fontSize: '13px' }}
                                            >
                                                {f}
                                            </div>
                                        ))}
                                    </div>

                                    {renderFrequencyContent()}

                                    <div style={{ 
                                        marginTop: '20px',
                                        background: 'var(--color-bg)',
                                        border: '1px solid var(--color-border)',
                                        borderRadius: '10px',
                                        padding: '14px 16px'
                                    }}>
                                        <label style={{ 
                                            display: 'flex', alignItems: 'center', gap: '6px',
                                            fontSize: '11px', fontWeight: 700, 
                                            color: 'var(--color-text-muted)', 
                                            textTransform: 'uppercase', letterSpacing: '0.05em',
                                            marginBottom: '12px'
                                        }}>
                                            <span>📧</span> RECIPIENT LIST
                                        </label>

                                        {/* Tag/Chip Container */}
                                        <div style={{ 
                                            display: 'flex', flexWrap: 'wrap', gap: '6px', 
                                            marginBottom: targetEmails.length > 0 ? '12px' : '0',
                                            minHeight: targetEmails.length > 0 ? 'auto' : '0'
                                        }}>
                                            {targetEmails.map((email, idx) => (
                                                <div key={idx} style={{ 
                                                    background: 'rgba(120, 120, 212, 0.15)', 
                                                    border: '1px solid rgba(120, 120, 212, 0.3)',
                                                    color: 'var(--color-primary)',
                                                    padding: '4px 10px',
                                                    borderRadius: '6px',
                                                    fontSize: '12px',
                                                    display: 'flex',
                                                    alignItems: 'center',
                                                    gap: '8px',
                                                    fontWeight: 600
                                                }}>
                                                    {email}
                                                    <span 
                                                        onClick={() => removeEmail(email)}
                                                        style={{ cursor: 'pointer', opacity: 0.6, fontSize: '14px' }}
                                                    >
                                                        ✕
                                                    </span>
                                                </div>
                                            ))}
                                        </div>

                                        <div style={{ position: 'relative' }}>
                                            <input
                                                type="text"
                                                placeholder={targetEmails.length === 0 ? "Enter email and press Enter..." : "Add another email..."}
                                                value={emailInputValue}
                                                onChange={(e) => setEmailInputValue(e.target.value)}
                                                onKeyDown={(e) => {
                                                    if (e.key === 'Enter' || e.key === ',') {
                                                        e.preventDefault();
                                                        addEmail();
                                                    }
                                                }}
                                                onBlur={addEmail}
                                                style={{ 
                                                    width: '100%',
                                                    padding: '12px 14px',
                                                    background: 'var(--color-bg-secondary)', 
                                                    color: 'var(--color-text)', 
                                                    border: '1px solid var(--color-border)', 
                                                    borderRadius: '8px', 
                                                    outline: 'none', 
                                                    fontSize: '14px',
                                                    transition: 'border-color 0.2s'
                                                }}
                                            />
                                            <div style={{ position: 'absolute', right: '12px', top: '50%', transform: 'translateY(-50%)', opacity: emailInputValue ? 1 : 0, transition: 'opacity 0.2s', fontSize: '10px', color: 'var(--color-text-muted)', fontWeight: 600 }}>
                                                PRESS ENTER ⏎
                                            </div>
                                        </div>
                                        
                                        <p style={{ fontSize: '10px', color: 'var(--color-text-muted)', marginTop: '8px' }}>
                                            PDF reports will be sent to all listed recipients.
                                        </p>
                                    </div>

                                    <div style={{ display: 'flex', gap: '12px', marginTop: '20px' }}>
                                        <button onClick={() => setStep(2)} style={{ flex: 1, padding: '12px', borderRadius: '8px', background: 'transparent', border: '1px solid var(--color-border)', color: 'var(--color-text)', cursor: 'pointer' }}>Back</button>
                                        <Button 
                                            variant="primary" 
                                            style={{ flex: 2 }} 
                                            onClick={handleSave} 
                                            disabled={submitting || targetEmails.length === 0}
                                        >
                                            {submitting ? 'Initializing First Audit...' : 'Finalize & Run First Audit'}
                                        </Button>
                                    </div>
                                </div>
                            )}
                        </div>
                    )}

                    <style>{`
                        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
                        @keyframes slideIn { from { transform: translateX(20px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
                        @keyframes scaleUp { from { transform: scale(0.9); opacity: 0; } to { transform: scale(1); opacity: 1; } }
                    `}</style>
                </Card>
            </div>
        </div>
    );
};

export default ScheduleModal;
