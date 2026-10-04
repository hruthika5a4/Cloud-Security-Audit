const express = require('express');
const router = express.Router();
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-local-key-for-jwt';

// Middleware to protect routes and extract user
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
        req.user = user;
        next();
    });
};

// Create or update a schedule
router.post('/', authenticateToken, async (req, res) => {
    const { projectId, provider, credentials, frequency, time, daysOfWeek, dayOfMonth, timezoneOffset, targetEmail } = req.body;
    
    if (!frequency || !time) {
        return res.status(400).json({ error: 'Frequency and time are required.' });
    }

    try {
        const computeNextRun = (freq, t, days, mDay, tzOffset = 0) => {
            const now = new Date();
            const localNow = new Date(now.getTime() - tzOffset * 60000);
            const [hours, minutes] = t.split(':').map(Number);
            
            let nextLocal = new Date(Date.UTC(localNow.getUTCFullYear(), localNow.getUTCMonth(), localNow.getUTCDate(), hours, minutes, 0));

            if (nextLocal <= localNow) {
                if (freq === 'daily') nextLocal.setUTCDate(nextLocal.getUTCDate() + 1);
                else if (freq === 'weekly') {
                    nextLocal.setUTCDate(nextLocal.getUTCDate() + 1);
                } else if (freq === 'monthly') nextLocal.setUTCMonth(nextLocal.getUTCMonth() + 1);
            }

            // More complex weekly logic relative to user's local day boundaries
            if (freq === 'weekly' && days && days.length > 0) {
                const dayMap = { Sunday: 0, Monday: 1, Tuesday: 2, Wednesday: 3, Thursday: 4, Friday: 5, Saturday: 6 };
                const dayIndices = days.map(d => dayMap[d]);
                for(let i=0; i<8; i++) {
                    const checkDate = new Date(Date.UTC(localNow.getUTCFullYear(), localNow.getUTCMonth(), localNow.getUTCDate() + i, hours, minutes, 0));
                    if (checkDate > localNow && dayIndices.includes(checkDate.getUTCDay())) {
                         nextLocal = checkDate;
                         break;
                    }
                }
            }

            // Monthly logic aligned to user's timezone date
            if (freq === 'monthly' && mDay) {
                let nextMonth = new Date(Date.UTC(localNow.getUTCFullYear(), localNow.getUTCMonth(), mDay, hours, minutes, 0));
                if (nextMonth <= localNow) nextMonth.setUTCMonth(nextMonth.getUTCMonth() + 1);
                nextLocal = nextMonth;
            }

            // Convert back to true UTC for tracking and storage
            return new Date(nextLocal.getTime() + tzOffset * 60000);
        };

        const nextRun = computeNextRun(frequency, time, daysOfWeek, dayOfMonth, timezoneOffset || 0);
        let finalProjectId = projectId;

        // If no project ID provided, we create a new project for this automation
        if (!finalProjectId) {
            let projectName = 'Automated ' + (provider || 'GCP') + ' Project';
            // Try to extract project id from GCP json if possible
            if (provider === 'gcp' && credentials) {
                try {
                    const parsed = JSON.parse(credentials);
                    if (parsed.project_id) projectName = parsed.project_id;
                } catch (e) {}
            }
            
            const newProj = await prisma.project.create({
                data: {
                    name: projectName,
                    provider: provider || 'gcp',
                    credentials: credentials,
                    userId: req.user.userId
                }
            });
            finalProjectId = newProj.id;
        }

        const schedule = await prisma.auditSchedule.create({
            data: {
                frequency,
                time,
                daysOfWeek,
                dayOfMonth,
                credentials, 
                nextRun,
                targetEmail,
                userId: req.user.userId,
                projectId: finalProjectId
            }
        });

        res.json(schedule);

        // --- IMMEDIATE TRIGGER ---
        // As requested: Trigger the first audit immediately upon configuration
        (async () => {
            console.log(`[Schedules] 🚀 Triggering first audit for new schedule: ${schedule.id}`);
            try {
                const { runGcpScan, runAwsScan, sendAuditEmail, ensureProjectLinked } = require('../services/scheduler');
                
                // Fetch full record with user details for email
                const fullSchedule = await prisma.auditSchedule.findUnique({
                    where: { id: schedule.id },
                    include: { project: true, user: true }
                });

                const credentialsSource = fullSchedule.credentials || (fullSchedule.project && fullSchedule.project.credentials);
                if (!credentialsSource) return;

                const resolvedProjectId = await ensureProjectLinked(fullSchedule, credentialsSource);
                if (!resolvedProjectId) return;

                const provider = fullSchedule.project ? fullSchedule.project.provider : 'gcp';
                
                let scanResult = null;
                if (provider === 'gcp') {
                    scanResult = await runGcpScan({ credentials: credentialsSource, projectId: resolvedProjectId });
                } else if (provider === 'aws') {
                    scanResult = await runAwsScan({ credentials: credentialsSource, projectId: resolvedProjectId });
                }
                
                if (scanResult) {
                    const emailToUse = fullSchedule.targetEmail || fullSchedule.user.email;
                    const projectName = fullSchedule.project ? fullSchedule.project.name : 'First Automated Scan';
                    await sendAuditEmail(emailToUse, scanResult, projectName);
                    
                    // Update lastRun so the UI shows it's been initialized
                    await prisma.auditSchedule.update({
                        where: { id: schedule.id },
                        data: { lastRun: new Date() }
                    });
                }
            } catch (err) {
                console.error(`[Schedules] First audit failed for ${schedule.id}:`, err);
            }
        })();
    } catch (err) {
        console.error('[Schedules] Create error:', err);
        res.status(500).json({ error: 'Failed to save schedule.' });
    }
});

// Get user's schedules
router.get('/', authenticateToken, async (req, res) => {
    try {
        const schedules = await prisma.auditSchedule.findMany({
            where: { userId: req.user.userId },
            include: { project: true }
        });
        res.json(schedules);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch schedules.' });
    }
});

// Toggle a schedule (Active/Inactive)
router.patch('/:id/toggle', authenticateToken, async (req, res) => {
    try {
        const schedule = await prisma.auditSchedule.findUnique({
            where: { id: req.params.id }
        });

        if (!schedule || schedule.userId !== req.user.userId) {
            return res.status(404).json({ error: 'Schedule not found.' });
        }

        const updated = await prisma.auditSchedule.update({
            where: { id: schedule.id },
            data: { isActive: !schedule.isActive }
        });

        res.json(updated);
    } catch (err) {
        res.status(500).json({ error: 'Failed to toggle schedule.' });
    }
});

// Delete a schedule
router.delete('/:id', authenticateToken, async (req, res) => {
    try {
        const schedule = await prisma.auditSchedule.findUnique({
            where: { id: req.params.id }
        });

        if (!schedule || schedule.userId !== req.user.userId) {
            return res.status(404).json({ error: 'Schedule not found.' });
        }

        await prisma.auditSchedule.delete({
            where: { id: schedule.id }
        });

        res.json({ message: 'Schedule deleted successfully.' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete schedule.' });
    }
});

// Manual Trigger: Run a schedule immediately
router.post('/:id/run', authenticateToken, async (req, res) => {
    try {
        const schedule = await prisma.auditSchedule.findUnique({
            where: { id: req.params.id },
            include: { project: true, user: true }
        });
        
        if (!schedule || schedule.userId !== req.user.userId) {
            return res.status(404).json({ error: 'Schedule not found.' });
        }
        
        // Use the scheduler's logic to run the scan
        const { runGcpScan, runAwsScan, sendAuditEmail, ensureProjectLinked } = require('../services/scheduler');
        
        const credentialsSource = schedule.credentials || (schedule.project && schedule.project.credentials);
        if (!credentialsSource) {
            return res.status(400).json({ error: 'No credentials found for this automation.' });
        }
        
        const resolvedProjectId = await ensureProjectLinked(schedule, credentialsSource);
        if (!resolvedProjectId) {
            return res.status(500).json({ error: 'Failed to link project for scan.' });
        }
        
        const provider = schedule.project ? schedule.project.provider : 'gcp';
        
        // Return immediate acceptance
        res.json({ message: 'Manual audit triggered! Report will be sent to your email list momentarily.' });
        
        // Execute in background
        (async () => {
            try {
                let scanResult = null;
                if (provider === 'gcp') {
                    scanResult = await runGcpScan({ credentials: credentialsSource, projectId: resolvedProjectId });
                } else if (provider === 'aws') {
                    scanResult = await runAwsScan({ credentials: credentialsSource, projectId: resolvedProjectId });
                }
                
                if (scanResult) {
                    const emailToUse = schedule.targetEmail || schedule.user.email;
                    const projectName = schedule.project ? schedule.project.name : 'Manual Triggered Scan';
                    await sendAuditEmail(emailToUse, scanResult, projectName);
                }
            } catch (err) {
                console.error(`[Schedules] Manual run failed for ${schedule.id}:`, err);
            }
        })();
        
    } catch (err) {
        console.error('[Schedules] Run error:', err);
        res.status(500).json({ error: 'Failed to trigger manual scan.' });
    }
});

module.exports = router;
