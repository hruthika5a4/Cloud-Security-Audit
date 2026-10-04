require('dotenv').config();
const cron = require('node-cron');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { initializeGcpClients } = require('./gcp/auth');
const { auditStorageBuckets } = require('./gcp/auditors/storageAuditor');
const { auditVMs } = require('./gcp/auditors/vmAuditor');
const { auditIAM } = require('./gcp/auditors/iamAuditor');
const { auditCloudSQL } = require('./gcp/auditors/sqlAuditor');
const { auditNetworking } = require('./gcp/auditors/networkingAuditor');
const { auditBigQuery } = require('./gcp/auditors/bigqueryAuditor');
const { auditKMS } = require('./gcp/auditors/kmsAuditor');
const { auditApiKeys } = require('./gcp/auditors/apiKeysAuditor');
const { auditEssentialContacts } = require('./gcp/auditors/essentialContactsAuditor');
const { auditDns } = require('./gcp/auditors/dnsAuditor');
const { auditLogging } = require('./gcp/auditors/loggingAuditor');
const { auditDataproc } = require('./gcp/auditors/dataprocAuditor');
const { auditGKE } = require('./gcp/auditors/gkeAuditor');
const { auditLB } = require('./gcp/auditors/lbAuditor');
const { auditServerless } = require('./gcp/auditors/serverlessAuditor');
const { auditNetworkingDepth } = require('./gcp/auditors/networkingDepthAuditor');
const { auditAwsIam, auditAwsEc2, auditAwsS3 } = require('./awsScanner');
const { generatePDF } = require('../routes/reports');
const { generateExcelReport } = require('./excelGenerator');
const nodemailer = require('nodemailer');

// Use structured transporter matching reports.js for higher reliability
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: process.env.SMTP_PORT || 587,
    secure: false, // true for 465, false for other ports
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});

// Helper to send email with PDF attachment
const sendAuditEmail = async (userEmail, scanData, projectName) => {
    console.log(`[Scheduler] 📧 Preparing to send audit report to: ${userEmail}`);
    
    if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
        console.error('[Scheduler] ERROR: SMTP_USER or SMTP_PASS is missing!');
        return;
    }

    try {
        console.log(`[Scheduler] 📄 Generating PDF for "${projectName}"...`);
        const pdfScanData = {
            score: scanData.score,
            vulnerabilities: typeof scanData.findings === 'string' ? JSON.parse(scanData.findings) : (scanData.findings || scanData.vulnerabilities || []),
            scanned: scanData.scannedResources || scanData.scanned || 0
        };
        const pdfBuffer = await generatePDF(pdfScanData, userEmail, projectName);
        
        console.log(`[Scheduler] 📊 Generating Excel for "${projectName}"...`);
        const excelBuffer = await generateExcelReport(pdfScanData, projectName);

        console.log(`[Scheduler] 📨 Sending SMTP mail via ${process.env.SMTP_HOST}...`);
        await transporter.sendMail({
            from: `"AuditScope Automation" <${process.env.SMTP_USER}>`,
            to: userEmail,
            subject: `[Automated] Security Audit: ${projectName} — Score ${scanData.score}%`,
            html: `
                <div style="font-family: sans-serif; color: #333; line-height: 1.6;">
                    <h2 style="color: #4f46e5;">Cloud Security Audit Report</h2>
                    <p>Hello,</p>
                    <p>The automated security audit for project <strong>${projectName}</strong> has been completed.</p>
                    
                    <div style="margin: 20px 0; padding: 15px; background: #f8fafc; border-radius: 8px; border-left: 4px solid #4f46e5;">
                        <p style="margin: 0;"><strong>Security Score:</strong> ${scanData.score}%</p>
                        <p style="margin: 5px 0 0 0;"><strong>Findings:</strong> ${scanData.criticalCount || 0} Critical, ${scanData.highCount || 0} High</p>
                    </div>

                    <p>Please find the detailed PDF and Excel reports attached to this email.</p>
                    
                    <hr style="border: 0; border-top: 1px solid #e2e8f0; margin: 30px 0;" />
                    <p style="font-size: 12px; color: #64748b;">This is an automated report from Security Audit Accelerator.</p>
                </div>
            `,
            attachments: [
                {
                    filename: `Security_Audit_${projectName.replace(/\s+/g, '_')}.pdf`,
                    content: pdfBuffer,
                    contentType: 'application/pdf'
                },
                {
                    filename: `Security_Audit_${projectName.replace(/\s+/g, '_')}.xlsx`,
                    content: excelBuffer,
                    contentType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                }
            ]
        });
        console.log(`[Scheduler] ✅ Email successfully delivered to ${userEmail}`);
    } catch (err) {
        console.error('[Scheduler] ❌ sendAuditEmail failed:', err);
        throw err;
    }
};

/**
 * Ensure a project record exists for this schedule.
 * Returns the project ID that should be used for saving the scan.
 */
const ensureProjectLinked = async (schedule, credentialsSource) => {
    // If the schedule already has a projectId, use it
    if (schedule.projectId) return schedule.projectId;

    // Otherwise create a new Project record so the scan can be stored
    console.log(`[Scheduler] No projectId on schedule ${schedule.id}, creating a project record...`);
    try {
        let projectName = 'Automated Scan';
        const provider = schedule.project?.provider || 'gcp';

        if (provider === 'gcp' && credentialsSource) {
            try {
                const parsed = typeof credentialsSource === 'string' ? JSON.parse(credentialsSource) : credentialsSource;
                if (parsed.project_id) projectName = parsed.project_id;
            } catch (e) {}
        } else if (provider === 'aws' && credentialsSource) {
            try {
                const parsed = typeof credentialsSource === 'string' ? JSON.parse(credentialsSource) : credentialsSource;
                if (parsed.accessKeyId) projectName = `AWS Project (${parsed.accessKeyId.substring(0, 6)}...)`;
            } catch (e) {}
        }

        const newProject = await prisma.project.create({
            data: {
                name: projectName,
                provider: provider,
                credentials: typeof credentialsSource === 'string' ? credentialsSource : JSON.stringify(credentialsSource),
                userId: schedule.userId
            }
        });

        // Link the schedule to this new project for future runs
        await prisma.auditSchedule.update({
            where: { id: schedule.id },
            data: { projectId: newProject.id }
        });

        console.log(`[Scheduler] Created & linked project "${projectName}" (${newProject.id}) to schedule ${schedule.id}`);
        return newProject.id;
    } catch (err) {
        console.error('[Scheduler] Failed to create project record:', err);
        return null;
    }
};

const runGcpScan = async ({ credentials, projectId }) => {
    try {
        const parsedCreds = typeof credentials === 'string' ? JSON.parse(credentials) : credentials;
        const clients = initializeGcpClients(parsedCreds);
        const gcpProjectId = clients.projectId;

        const auditModules = [
            { name: 'Storage', fn: () => auditStorageBuckets(clients.storageClient, gcpProjectId) },
            { name: 'VMs', fn: () => auditVMs(clients.computeClient, clients.projectClient, gcpProjectId) },
            { name: 'IAM', fn: () => auditIAM(clients.googleAuthClient, gcpProjectId) },
            { name: 'SQL', fn: () => auditCloudSQL(clients.googleAuthClient, gcpProjectId) },
            { name: 'Networking', fn: () => auditNetworking(clients.networksClient, clients.firewallsClient, clients.subnetworksClient, clients.backendServicesClient, gcpProjectId) },
            { name: 'BigQuery', fn: () => auditBigQuery(clients.bigQueryClient, gcpProjectId) },
            { name: 'KMS', fn: () => auditKMS(clients.googleAuthClient, gcpProjectId) },
            { name: 'API Keys', fn: () => auditApiKeys(clients.googleAuthClient, gcpProjectId) },
            { name: 'Essential Contacts', fn: () => auditEssentialContacts(clients.googleAuthClient, gcpProjectId) },
            { name: 'DNS', fn: () => auditDns(clients.googleAuthClient, gcpProjectId) },
            { name: 'Logging', fn: () => auditLogging(clients.googleAuthClient, gcpProjectId) },
            { name: 'Dataproc', fn: () => auditDataproc(clients.googleAuthClient, gcpProjectId) },
            { name: 'GKE', fn: () => auditGKE(clients.googleAuthClient, gcpProjectId) },
            { name: 'Load Balancers', fn: () => auditLB(clients.googleAuthClient, gcpProjectId) },
            { name: 'Serverless', fn: () => auditServerless(clients.googleAuthClient, gcpProjectId) },
            { name: 'Networking Depth', fn: () => auditNetworkingDepth(clients.googleAuthClient, gcpProjectId) }
        ];

        console.log(`[GCP Scan] 🔍 Launching ${auditModules.length} auditors for project "${gcpProjectId}"...`);

        const auditPromises = auditModules.map(async (mod) => {
            const start = Date.now();
            try {
                // Add a local timeout (30s) per module
                const timeoutPromise = new Promise((_, reject) => 
                    setTimeout(() => reject(new Error(`Timeout after 30s`)), 30000)
                );
                const result = await Promise.race([mod.fn(), timeoutPromise]);
                const duration = ((Date.now() - start) / 1000).toFixed(1);
                console.log(`[GCP Scan] ✅ Completed: ${mod.name} (${duration}s)`);
                return result;
            } catch (err) {
                console.error(`[GCP Scan] ⚠️  Module ${mod.name} failed/timed out:`, err.message);
                return { findings: [], scannedCount: 0, skipped: true, error: err.message };
            }
        });

        const results = await Promise.all(auditPromises);
        console.log(`[GCP Scan] ✨ All modules processed. Aggregating results...`);
        let allFindings = [];
        let totalScanned = 0;
        let skippedChecks = [];
        // Precise mapping of the 77 internal security rules across all GCP modules
        const auditorMeta = [
          { name: 'Storage',            checks: 4 },
          { name: 'VMs',                checks: 10 },
          { name: 'IAM',                checks: 8 },
          { name: 'SQL',                checks: 6 },
          { name: 'Networking',         checks: 8 },
          { name: 'BigQuery',           checks: 3 },
          { name: 'KMS',                checks: 3 },
          { name: 'API Keys',           checks: 2 },
          { name: 'Essential Contacts', checks: 1 },
          { name: 'DNS',                checks: 2 },
          { name: 'Logging',            checks: 12 },
          { name: 'Dataproc',           checks: 2 },
          { name: 'Kubernetes (GKE)',   checks: 6 },
          { name: 'Load Balancers',     checks: 4 },
          { name: 'Serverless',         checks: 3 },
          { name: 'Deep Networking',    checks: 1 }
        ];

        let totalCheckpoints = 0;
        let skippedCheckpoints = 0;

        results.forEach((result, idx) => {
            const meta = auditorMeta[idx];
            
            allFindings = allFindings.concat(result.vulnerabilities || result.findings || []);
            const resourceCount = result.scannedCount || 0;
            totalScanned += resourceCount;
            
            // Map findings to checkpoints for score calculation
            const serviceValidations = Math.max(1, resourceCount * meta.checks);
            totalCheckpoints += serviceValidations;

            if (result.skipped || result.error) {
                skippedCheckpoints += serviceValidations;
                skippedChecks.push({
                    service: meta.name,
                    reason: result.reason || result.error || 'Check skipped'
                });
            }
        });

        const totalChecks = totalCheckpoints;
        const criticalCount = allFindings.filter(f => f.severity === 'Critical').length;
        const highCount = allFindings.filter(f => f.severity === 'High').length;
        const mediumCount = allFindings.filter(f => f.severity === 'Medium').length;
        const uniqueVulnerableResources = new Set(allFindings.map(f => f.resource)).size;

        let computedScore = 100;
        if (totalScanned > 0) {
            computedScore = Math.round(((totalScanned - uniqueVulnerableResources) / totalScanned) * 100);
            computedScore = Math.max(0, computedScore);
        }

        // Always save to history — we now always have a valid projectId
        if (projectId) {
            const savedScan = await prisma.scanHistory.create({
                data: {
                    score: computedScore,
                    scannedResources: totalScanned,
                    totalChecks: totalChecks,
                    skippedChecks: JSON.stringify(skippedChecks),
                    criticalCount,
                    highCount,
                    mediumCount,
                    findings: JSON.stringify(allFindings),
                    projectId: projectId
                }
            });
            console.log(`[Scheduler] ✅ GCP scan saved. Score: ${computedScore}%, Checks: ${totalChecks - skippedChecks.length}/${totalChecks}`);
            return savedScan;
        }

        return { 
            score: computedScore, 
            scannedResources: totalScanned, 
            totalChecks, 
            skippedChecks: JSON.stringify(skippedChecks),
            criticalCount, 
            highCount, 
            mediumCount, 
            findings: JSON.stringify(allFindings) 
        };
    } catch (err) {
        console.error(`[Scheduler] GCP scan failed for project ${projectId}:`, err.message);
        return null;
    }
};

const runAwsScan = async ({ credentials, projectId }) => {
    try {
        const parsedCreds = typeof credentials === 'string' ? JSON.parse(credentials) : credentials;
        const auditPromises = [
            auditAwsIam(parsedCreds),
            auditAwsEc2(parsedCreds),
            auditAwsS3(parsedCreds)
        ];

        const results = await Promise.allSettled(auditPromises);
        let allFindings = [];
        let totalScanned = 0;

        results.forEach((result) => {
            if (result.status === 'fulfilled') {
                allFindings = allFindings.concat(result.value.findings || []);
                totalScanned += (result.value.scannedCount || 0);
            }
        });

        const criticalCount = allFindings.filter(f => f.severity === 'Critical').length;
        const highCount = allFindings.filter(f => f.severity === 'High').length;
        const mediumCount = allFindings.filter(f => f.severity === 'Medium').length;
        const uniqueVulnerableResources = new Set(allFindings.map(f => f.resource)).size;

        let computedScore = 100;
        if (totalScanned > 0) {
            computedScore = Math.round(((totalScanned - uniqueVulnerableResources) / totalScanned) * 100);
            computedScore = Math.max(0, computedScore);
        }

        // Always save to history — we now always have a valid projectId
        if (projectId) {
            const savedScan = await prisma.scanHistory.create({
                data: {
                    score: computedScore,
                    scannedResources: totalScanned,
                    criticalCount,
                    highCount,
                    mediumCount,
                    findings: JSON.stringify(allFindings),
                    projectId: projectId
                }
            });
            console.log(`[Scheduler] ✅ AWS scan saved for project ${projectId}. Score: ${computedScore}%`);
            return savedScan;
        }

        return { score: computedScore, scannedResources: totalScanned, criticalCount, highCount, mediumCount, findings: JSON.stringify(allFindings) };
    } catch (err) {
        console.error(`[Scheduler] AWS scan failed for project ${projectId}:`, err.message);
        return null;
    }
};

/**
 * Compute the next scheduled run time based on frequency settings.
 * All times are stored internally as UTC in the DB.
 */
const computeNextRun = (freq, t, days, mDay) => {
    const now = new Date();
    const [hours, minutes] = t.split(':').map(Number);

    // Build next run candidate: today at the specified UTC time
    let next = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), hours, minutes, 0));

    if (freq === 'daily') {
        // If time has already passed today, schedule for tomorrow
        if (next <= now) next.setUTCDate(next.getUTCDate() + 1);
    } else if (freq === 'weekly' && days && days.length > 0) {
        const dayMap = { Sunday: 0, Monday: 1, Tuesday: 2, Wednesday: 3, Thursday: 4, Friday: 5, Saturday: 6 };
        const dayIndices = days.map(d => dayMap[d]);
        // Find the next matching weekday (search up to 7 days ahead)
        let found = false;
        for (let i = 1; i <= 7; i++) {
            const checkDate = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + i, hours, minutes, 0));
            if (dayIndices.includes(checkDate.getUTCDay())) {
                next = checkDate;
                found = true;
                break;
            }
        }
        if (!found) next.setUTCDate(next.getUTCDate() + 7); // safety fallback
    } else if (freq === 'monthly' && mDay) {
        next = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), mDay, hours, minutes, 0));
        if (next <= now) next.setUTCMonth(next.getUTCMonth() + 1);
    } else {
        // Default: next day
        if (next <= now) next.setUTCDate(next.getUTCDate() + 1);
    }

    return next;
};

let isProcessing = false;

const startScheduler = () => {
    console.log('[Scheduler] ⏰ Starting scheduler service — checking for due audits...');

    // Check every minute
    cron.schedule('* * * * *', async () => {
        if (isProcessing) {
            console.log('[Scheduler] Tick skipped: Previous audit loop still running.');
            return;
        }

        const now = new Date();
        isProcessing = true;

        try {
            const dueSchedules = await prisma.auditSchedule.findMany({
                where: {
                    isActive: true,
                    nextRun: { lte: now }
                }
                // include removed to prevent whole-set crash due to orphan relations
            });

            if (dueSchedules.length === 0) {
                isProcessing = false;
                return;
            }

            console.log(`[Scheduler] 🚀 Found ${dueSchedules.length} due audit(s).`);

            for (const schedule of dueSchedules) {
                try {
                    // Fetch related data individually to isolate orphan errors
                    const user = await prisma.user.findUnique({ where: { id: schedule.userId } });
                    const project = schedule.projectId ? await prisma.project.findUnique({ where: { id: schedule.projectId } }) : null;

                    if (!user) {
                        console.warn(`[Scheduler] ⚠️ Skipping schedule ${schedule.id}: User ${schedule.userId} not found.`);
                        continue;
                    }

                    console.log(`[Scheduler] ─── Running audit for schedule: ${schedule.id}`);

                    // Update nextRun to far future IMMEDIATELY to prevent double-triggering
                    // if this scan takes longer than 60 seconds (next tick).
                    await prisma.auditSchedule.update({
                        where: { id: schedule.id },
                        data: { nextRun: new Date(now.getTime() + 1000 * 60 * 60 * 24) } // +1 day safety bump
                    });

                    const credentialsSource = schedule.credentials || (project && project.credentials);

                    if (!credentialsSource) {
                        console.error(`[Scheduler] ❌ No credentials found for ${schedule.id}`);
                        continue;
                    }

                    const resolvedProjectId = await ensureProjectLinked(schedule, credentialsSource);
                    if (!resolvedProjectId) continue;

                    const provider = project ? project.provider : 'gcp';
                    let scanResult = null;

                    if (provider === 'gcp') {
                        scanResult = await runGcpScan({ credentials: credentialsSource, projectId: resolvedProjectId });
                    } else if (provider === 'aws') {
                        scanResult = await runAwsScan({ credentials: credentialsSource, projectId: resolvedProjectId });
                    }

                    if (scanResult) {
                        const emailToUse = schedule.targetEmail || user.email;
                        const projectName = project ? project.name : 'Automated Scan';
                        await sendAuditEmail(emailToUse, scanResult, projectName);
                    }

                    // Compute and persist the ACTUAL next run time
                    const nextRun = computeNextRun(schedule.frequency, schedule.time, schedule.daysOfWeek, schedule.dayOfMonth);
                    await prisma.auditSchedule.update({
                        where: { id: schedule.id },
                        data: {
                            lastRun: now,
                            nextRun: nextRun
                        }
                    });

                    console.log(`[Scheduler] ✅ Finished schedule ${schedule.id}. Next: ${nextRun.toISOString()}`);
                } catch (err) {
                    console.error(`[Scheduler] Failed processing schedule ${schedule.id}:`, err);
                }
            }
        } catch (err) {
            console.error('[Scheduler] ❌ Critical loop error:', err);
        } finally {
            isProcessing = false;
        }
    });

    console.log('[Scheduler] ✅ Scheduler service started successfully.');
};

module.exports = { 
    startScheduler,
    runGcpScan,
    runAwsScan,
    sendAuditEmail,
    ensureProjectLinked
};
