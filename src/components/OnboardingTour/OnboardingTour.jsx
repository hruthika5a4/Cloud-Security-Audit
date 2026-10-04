import React, { useState, useEffect, useLayoutEffect, useCallback, useRef } from 'react';

// ─── Tour step definitions ────────────────────────────────────────────────────
const TOUR_STEPS = [
    {
        target: null,
        placement: 'center',
        icon: '👋',
        title: 'Welcome to AuditScope!',
        description: "You're all set! Let's take a quick tour so you know exactly how to run your first security audit and use every feature of the platform.",
        tag: 'Getting Started',
    },
    {
        target: 'tour-sidebar-dashboard',
        placement: 'right',
        icon: '📊',
        title: 'Dashboard',
        description: 'This is your command centre. After every scan, all your results appear here — security score, vulnerability breakdown, and a searchable findings table.',
        tag: 'Navigation',
    },
    {
        target: 'tour-navbar-provider',
        placement: 'bottom',
        icon: <svg viewBox="0 0 24 24" width="24" height="24"><path fill="currentColor" d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z"/></svg>,
        title: 'Choose Your Cloud Provider',
        description: 'Start by selecting your cloud platform. Currently supports Google Cloud Platform (GCP) and Amazon Web Services (AWS). Azure is coming soon.',
        tag: 'Step 1 of 2',
    },
    {
        target: 'tour-navbar-scan',
        placement: 'bottom',
        icon: '🔍',
        title: 'Run the Security Audit',
        description: "Click Scan to upload your credentials and kick off a full audit. AuditScope checks IAM roles, storage buckets, networking rules, compute VMs, and more — all in parallel.",
        tag: 'Step 2 of 2',
    },
    {
        target: 'tour-sidebar-projects',
        placement: 'right',
        icon: '📁',
        title: 'Projects',
        description: 'Every unique cloud project you scan is automatically saved here. Click a project card to see all its past audit results and track your security score over time.',
        tag: 'Navigation',
    },
    {
        target: 'tour-sidebar-automation',
        placement: 'right',
        icon: '⏰',
        title: 'Automation Hub',
        description: "Set up recurring scheduled audits — daily, weekly, or monthly. Even when you're not logged in, AuditScope will scan and send the PDF report straight to your email.",
        tag: 'Navigation',
    },
    {
        target: 'tour-sidebar-history',
        placement: 'right',
        icon: '⏱️',
        title: 'Scan History',
        description: 'Every audit is stored and archived here. Open any historical scan directly on the Dashboard to review old findings and compare security scores across time.',
        tag: 'Navigation',
    },
    {
        target: 'tour-sidebar-settings',
        placement: 'right',
        icon: '⚙️',
        title: 'Settings',
        description: 'Update your profile picture, display name, and email preferences here. You can also replay this tour anytime from the Settings page.',
        tag: 'Navigation',
    },
    {
        target: 'tour-navbar-profile',
        placement: 'bottom',
        icon: '👤',
        title: 'Profile & Logout',
        description: 'Click your avatar to open the profile menu. You can see your account details and securely log out of AuditScope from here.',
        tag: 'Account',
    },
    {
        target: null,
        placement: 'center',
        icon: '🚀',
        title: "You're all set!",
        description: "That's the full tour. Select a cloud provider and hit Scan to run your very first security audit. You can replay this walkthrough anytime from Settings → Product Tour.",
        tag: 'Done',
    },
];

const PAD = 12; // spotlight padding in px
const CARD_W = 380;

// ─── 4-panel spotlight: returns the 4 rects that surround the target ──────────
const getPanels = (rect, vpW, vpH) => {
    if (!rect) return null;
    const { top, left, bottom, right } = {
        top: rect.top - PAD,
        left: rect.left - PAD,
        bottom: rect.bottom + PAD,
        right: rect.right + PAD,
    };
    return {
        top:    { top: 0,      left: 0,     width: vpW,          height: Math.max(0, top) },
        bottom: { top: bottom, left: 0,     width: vpW,          height: Math.max(0, vpH - bottom) },
        left:   { top: top,    left: 0,     width: Math.max(0, left),   height: Math.max(0, bottom - top) },
        right:  { top: top,    left: right, width: Math.max(0, vpW - right), height: Math.max(0, bottom - top) },
        spotlight: { top, left, width: rect.width + PAD * 2, height: rect.height + PAD * 2 },
    };
};

// ─── Card position ─────────────────────────────────────────────────────────────
const getCardPos = (rect, placement, vpW, vpH) => {
    const CARD_H = 310;
    if (placement === 'center' || !rect) {
        return { position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)' };
    }
    if (placement === 'right') {
        const left = rect.right + PAD + 18;
        let top = rect.top + rect.height / 2 - CARD_H / 2;
        top = Math.max(16, Math.min(top, vpH - CARD_H - 16));
        if (left + CARD_W > vpW - 12) {
            // Not enough room on right → place below
            const cardLeft = Math.max(16, Math.min(rect.left, vpW - CARD_W - 16));
            return { position: 'fixed', top: rect.bottom + PAD + 16, left: cardLeft };
        }
        return { position: 'fixed', top, left };
    }
    if (placement === 'bottom') {
        let left = rect.left + rect.width / 2 - CARD_W / 2;
        left = Math.max(16, Math.min(left, vpW - CARD_W - 16));
        const top = rect.bottom + PAD + 18;
        return { position: 'fixed', top, left };
    }
    return { position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)' };
};

// ──────────────────────────────────────────────────────────────────────────────
const OnboardingTour = () => {
    const [active, setActive] = useState(false);
    const [step, setStep] = useState(0);
    const [panels, setPanels] = useState(null);
    const [vpSize, setVpSize] = useState({ w: window.innerWidth, h: window.innerHeight });
    const rafRef = useRef(null);
    const totalSteps = TOUR_STEPS.length;

    // Trigger only for new users
    useEffect(() => {
        if (!localStorage.getItem('auditscope_tour_done')) {
            const t = setTimeout(() => setActive(true), 700);
            return () => clearTimeout(t);
        }
    }, []);

    // Viewport resize
    useEffect(() => {
        const fn = () => setVpSize({ w: window.innerWidth, h: window.innerHeight });
        window.addEventListener('resize', fn);
        return () => window.removeEventListener('resize', fn);
    }, []);

    // Measure target on every animation frame
    const measure = useCallback(() => {
        const s = TOUR_STEPS[step];
        if (!s?.target) { setPanels(null); return; }
        const el = document.querySelector(`[data-tour="${s.target}"]`);
        if (el) setPanels(getPanels(el.getBoundingClientRect(), window.innerWidth, window.innerHeight));
        else setPanels(null);
    }, [step]);

    useLayoutEffect(() => {
        if (!active) return;
        let running = true;
        const loop = () => { measure(); if (running) rafRef.current = requestAnimationFrame(loop); };
        rafRef.current = requestAnimationFrame(loop);
        return () => { running = false; cancelAnimationFrame(rafRef.current); };
    }, [active, measure]);

    // Keyboard shortcuts
    useEffect(() => {
        if (!active) return;
        const fn = (e) => {
            if (e.key === 'ArrowRight' || e.key === 'Enter') advance();
            if (e.key === 'ArrowLeft') back();
            if (e.key === 'Escape') dismiss();
        };
        window.addEventListener('keydown', fn);
        return () => window.removeEventListener('keydown', fn);
    }, [active, step]);

    const dismiss = () => { localStorage.setItem('auditscope_tour_done', 'true'); setActive(false); };
    const advance = () => step < totalSteps - 1 ? setStep(s => s + 1) : dismiss();
    const back = () => step > 0 && setStep(s => s - 1);

    if (!active) return null;

    const cur = TOUR_STEPS[step];
    const isFirst = step === 0;
    const isLast = step === totalSteps - 1;
    const rect = panels?.spotlight ?? null;
    const cardStyle = getCardPos(rect, cur.placement, vpSize.w, vpSize.h);
    const panelStyle = { position: 'fixed', background: 'rgba(5,7,18,0.78)', zIndex: 9000, pointerEvents: 'auto', transition: 'all 0.3s cubic-bezier(0.4,0,0.2,1)' };

    return (
        <>
            {/* ── 4-panel spotlight overlay ── */}
            {panels ? (
                <>
                    <div style={{ ...panelStyle, ...panels.top }} onClick={advance} />
                    <div style={{ ...panelStyle, ...panels.bottom }} onClick={advance} />
                    <div style={{ ...panelStyle, ...panels.left }} onClick={advance} />
                    <div style={{ ...panelStyle, ...panels.right }} onClick={advance} />
                    {/* Glowing ring around spotlight */}
                    <div style={{
                        position: 'fixed',
                        zIndex: 9001,
                        top: panels.spotlight.top,
                        left: panels.spotlight.left,
                        width: panels.spotlight.width,
                        height: panels.spotlight.height,
                        borderRadius: '8px',
                        border: '2px solid rgba(99,102,241,0.85)',
                        boxShadow: '0 0 0 3px rgba(99,102,241,0.12), inset 0 0 0 1px rgba(99,102,241,0.1)',
                        pointerEvents: 'none',
                        transition: 'all 0.3s cubic-bezier(0.4,0,0.2,1)',
                        animation: 'glow 2.4s ease-in-out infinite',
                    }} />
                    {/* Bounce arrow */}
                    {cur.placement === 'right' && (
                        <div style={{ position: 'fixed', zIndex: 9002, pointerEvents: 'none',
                            top: panels.spotlight.top + panels.spotlight.height / 2 - 12,
                            left: panels.spotlight.left + panels.spotlight.width + 4,
                            fontSize: '20px', color: '#6366f1', animation: 'bounceX 1.1s ease-in-out infinite',
                            filter: 'drop-shadow(0 0 8px rgba(99,102,241,0.7))' }}>→</div>
                    )}
                    {cur.placement === 'bottom' && (
                        <div style={{ position: 'fixed', zIndex: 9002, pointerEvents: 'none',
                            top: panels.spotlight.top + panels.spotlight.height + 4,
                            left: panels.spotlight.left + panels.spotlight.width / 2 - 12,
                            fontSize: '20px', color: '#6366f1', animation: 'bounceY 1.1s ease-in-out infinite',
                            filter: 'drop-shadow(0 0 8px rgba(99,102,241,0.7))' }}>↓</div>
                    )}
                </>
            ) : (
                /* Full-screen overlay for centred steps */
                <div style={{ position: 'fixed', inset: 0, background: 'rgba(5,7,18,0.72)', backdropFilter: 'blur(6px)', zIndex: 9000, pointerEvents: 'auto' }} onClick={advance} />
            )}

            {/* ── Tour Card ── */}
            <div
                style={{ ...cardStyle, width: CARD_W, zIndex: 9010, pointerEvents: 'auto' }}
                onClick={e => e.stopPropagation()}
            >
                <div style={{
                    background: '#ffffff',
                    borderRadius: '14px',
                    boxShadow: '0 20px 60px rgba(0,0,0,0.22), 0 4px 16px rgba(99,102,241,0.14)',
                    overflow: 'hidden',
                    fontFamily: "'Inter', 'Segoe UI', sans-serif",
                    animation: 'cardPop 0.28s cubic-bezier(0.34,1.56,0.64,1)',
                }}>

                    {/* ── Coloured header banner ── */}
                    <div style={{
                        background: 'linear-gradient(135deg, #4f46e5 0%, #7c3aed 60%, #a855f7 100%)',
                        padding: '20px 22px 16px',
                    }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                <div style={{
                                    background: 'rgba(255,255,255,0.18)',
                                    backdropFilter: 'blur(4px)',
                                    borderRadius: '10px',
                                    width: '42px', height: '42px',
                                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                                    fontSize: '22px', flexShrink: 0,
                                }}>
                                    {cur.icon}
                                </div>
                                <div>
                                    <div style={{ fontSize: '10px', fontWeight: 700, color: 'rgba(255,255,255,0.65)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: '3px' }}>
                                        {cur.tag}
                                    </div>
                                    <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: '#fff', lineHeight: 1.25 }}>
                                        {cur.title}
                                    </h3>
                                </div>
                            </div>
                            <button
                                onClick={dismiss}
                                style={{ background: 'rgba(255,255,255,0.15)', border: 'none', borderRadius: '6px', color: 'rgba(255,255,255,0.8)', width: '28px', height: '28px', cursor: 'pointer', fontSize: '14px', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}
                            >✕</button>
                        </div>

                        {/* Step progress bar */}
                        <div style={{ marginTop: '14px', display: 'flex', gap: '4px' }}>
                            {TOUR_STEPS.map((_, i) => (
                                <div key={i} style={{
                                    flex: 1, height: '3px', borderRadius: '2px',
                                    background: i <= step ? 'rgba(255,255,255,0.9)' : 'rgba(255,255,255,0.22)',
                                    transition: 'background 0.3s',
                                }} />
                            ))}
                        </div>
                    </div>

                    {/* ── Card body ── */}
                    <div style={{ padding: '20px 22px' }}>
                        <p style={{ margin: '0 0 20px 0', fontSize: '14px', color: '#4b5563', lineHeight: 1.75 }}>
                            {cur.description}
                        </p>

                        {/* Hint about clicking overlay */}
                        {panels && !isLast && (
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 12px', background: '#f5f3ff', borderRadius: '8px', marginBottom: '16px', border: '1px solid #ede9fe' }}>
                                <span style={{ fontSize: '13px' }}>💡</span>
                                <span style={{ fontSize: '12px', color: '#7c3aed', fontWeight: 500 }}>You can click anywhere outside this card to advance</span>
                            </div>
                        )}

                        {/* ── Buttons row ── */}
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}>
                            {/* Skip */}
                            <button
                                onClick={dismiss}
                                style={{ background: 'none', border: 'none', color: '#9ca3af', cursor: 'pointer', fontSize: '13px', padding: '6px 0', fontFamily: 'inherit', transition: 'color 0.2s' }}
                                onMouseEnter={e => e.target.style.color = '#374151'}
                                onMouseLeave={e => e.target.style.color = '#9ca3af'}
                            >
                                Skip tour
                            </button>

                            {/* Right side: Back + Next/Done */}
                            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                                <span style={{ fontSize: '12px', color: '#d1d5db', fontWeight: 500 }}>
                                    {step + 1}/{totalSteps}
                                </span>
                                {!isFirst && (
                                    <button
                                        onClick={back}
                                        style={{
                                            padding: '9px 16px', borderRadius: '8px',
                                            background: '#f9fafb', border: '1px solid #e5e7eb',
                                            color: '#374151', cursor: 'pointer', fontSize: '13px', fontWeight: 600,
                                            fontFamily: 'inherit', transition: 'all 0.15s',
                                        }}
                                        onMouseEnter={e => { e.currentTarget.style.background = '#f3f4f6'; }}
                                        onMouseLeave={e => { e.currentTarget.style.background = '#f9fafb'; }}
                                    >
                                        ← Back
                                    </button>
                                )}
                                <button
                                    onClick={advance}
                                    style={{
                                        padding: '9px 22px', borderRadius: '8px',
                                        background: 'linear-gradient(135deg, #4f46e5, #7c3aed)',
                                        border: 'none', color: '#fff',
                                        cursor: 'pointer', fontSize: '13px', fontWeight: 700,
                                        fontFamily: 'inherit',
                                        boxShadow: '0 2px 8px rgba(99,102,241,0.35)',
                                        transition: 'all 0.15s',
                                    }}
                                    onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-1px)'; e.currentTarget.style.boxShadow = '0 4px 14px rgba(99,102,241,0.45)'; }}
                                    onMouseLeave={e => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = '0 2px 8px rgba(99,102,241,0.35)'; }}
                                >
                                    {isLast ? '🎉 Let\'s go!' : 'Next →'}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <style>{`
                @keyframes glow {
                    0%,100% { box-shadow: 0 0 0 3px rgba(99,102,241,0.12), 0 0 16px rgba(99,102,241,0.25); }
                    50%      { box-shadow: 0 0 0 5px rgba(99,102,241,0.08), 0 0 28px rgba(99,102,241,0.45); }
                }
                @keyframes cardPop {
                    0%   { opacity:0; transform: scale(0.94) translateY(10px); }
                    100% { opacity:1; transform: scale(1) translateY(0); }
                }
                @keyframes bounceX {
                    0%,100% { transform: translateX(0); }
                    50%     { transform: translateX(6px); }
                }
                @keyframes bounceY {
                    0%,100% { transform: translateY(0); }
                    50%     { transform: translateY(6px); }
                }
            `}</style>
        </>
    );
};

export default OnboardingTour;
