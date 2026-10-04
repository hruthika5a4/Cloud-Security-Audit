const express = require('express');
const PDFDocument = require('pdfkit');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const { generateExcelReport } = require('../services/excelGenerator');

const router = express.Router();
const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-local-key-for-jwt';

// Helper for Real Email Sending
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: process.env.SMTP_PORT || 587,
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token.' });
    req.user = user;
    next();
  });
};

const getServiceName = (resource) => {
  if (!resource) return 'Other';
  const match = resource.match(/^([^(]+)/);
  let sName = match ? match[1].trim() : 'Other';
  const lowerName = sName.toLowerCase();
  
  if (lowerName.includes('compute') || lowerName.includes('vm')) return 'Compute';
  if (lowerName.includes('iam') || lowerName.includes('service account')) return 'IAM';
  if (lowerName.includes('storage') || lowerName.includes('bucket')) return 'Storage';
  if (lowerName.includes('sql') || lowerName.includes('database') || lowerName.includes('rds')) return 'Database';
  if (lowerName.includes('network') || lowerName.includes('vpc') || lowerName.includes('firewall') || lowerName.includes('dns') || lowerName.includes('subnet')) return 'Networking';
  if (lowerName.includes('kubernetes') || lowerName.includes('gke') || lowerName.includes('eks')) return 'Kubernetes';
  if (lowerName.includes('kms') || lowerName.includes('key')) return 'KMS';
  if (lowerName.includes('func') || lowerName.includes('lambda') || lowerName.includes('serverless') || lowerName.includes('cloudrun')) return 'Serverless';
  if (lowerName.includes('load balancer') || lowerName.includes('backend service') || lowerName.includes('lb')) return 'Load Balancers';
  if (lowerName.includes('bigquery') || lowerName.includes('bq') || lowerName.includes('dataset') || lowerName.includes('table')) return 'BigQuery';
  if (lowerName.includes('dataproc')) return 'Dataproc';
  
  return sName;
};

const getCheckpointName = (id) => {
    if (!id) return 'General Check';
    const parts = id.split('-');
    const checkType = parts[2] ? parts[2].toUpperCase() : 'GENERAL';
    
    const mapping = {
        'PUBLIC': 'Check Public Access',
        'EXTERNAL': 'Check External Access',
        'ENCRYPTION': 'Check Encryption',
        'ROTATION': 'Check Key Rotation',
        'ADMIN': 'Check Admin Access',
        'SOD': 'Check Separation of Duties',
        'TOKEN': 'Check SA Tokens',
        'KEY': 'Check SA Keys',
        'SSL': 'Check SSL Policy',
        'IP': 'Check IP Config',
        'LOG': 'Check Logging',
        'LBLOG': 'Check LB Logging',
        'MONITOR': 'Check Monitoring',
        'FIREWALL': 'Check Firewall Rules',
        'VERSION': 'Check Software Version',
        'SA': 'Check Service Accounts',
        'GKE': 'Check Kubernetes',
        'FLOW': 'Check VPC Flow Logs',
        'ENDPOINT': 'Check API Endpoint',
        'ABAC': 'Check Legacy ABAC',
        'WORKLOAD': 'Check Workload Identity',
        'SHIELDED': 'Check Shielded Nodes',
        'BINARY': 'Check Binary Auth',
        'RDS': 'Check RDS Public',
        'EKS': 'Check EKS Public',
        'SERVERLESS': 'Check Serverless',
        'DATASET': 'Check BigQuery Dataset'
    };

    return mapping[checkType] || `Check: ${checkType.charAt(0).toUpperCase() + checkType.slice(1).toLowerCase()}`;
};

router.use(authenticateToken);

// Helper: generate the PDF buffer from scan data
function generatePDF(scanData, userName, projectId) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50, size: 'A4', bufferPages: true });
    const chunks = [];

    doc.on('data', (chunk) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    const indigo  = '#4f46e5';
    const darkBg  = '#0f172a';
    const slate50 = '#f8fafc';
    const slate100= '#f1f5f9';
    const slate200= '#e2e8f0';
    const slate600= '#475569';
    const slate800= '#1e293b';

    // ── HEADER ────────────────────────────────────────────────────────
    doc.rect(0, 0, doc.page.width, 110).fill(darkBg);
    doc.fontSize(22).fillColor('#ffffff').text('AuditScope', 50, 28, { continued: true });
    doc.fontSize(22).fillColor(indigo).text(' Security Report');
    doc.fontSize(9).fillColor('#94a3b8')
       .text(`Project: ${projectId}   |   Prepared for: ${userName}   |   ${new Date().toLocaleString()}`, 50, 58);

    // Provider badge
    const prov = (scanData.provider || 'gcp').toUpperCase();
    doc.roundedRect(50, 76, 60, 18, 4).fill('rgba(99,102,241,0.25)');
    doc.fontSize(8).fillColor('#a5b4fc').text(prov, 56, 81);

    doc.moveDown(1);

    // ── PROJECT OVERVIEW SECTION (when called from ProjectDetailsPage) ──
    const ps = scanData.projectSummary;
    let currentY = 130;

    if (ps) {
      // Section title
      doc.fontSize(12).fillColor(slate800).text('Project Overview', 50, currentY, { underline: false });
      doc.moveTo(50, currentY + 16).lineTo(doc.page.width - 50, currentY + 16).strokeColor(slate200).lineWidth(1).stroke();
      currentY += 26;

      // Stat boxes – 4 across
      const boxW = (doc.page.width - 100 - 30) / 4;
      const boxes = [
        { label: 'TOTAL SCANS',     value: String(ps.totalScans),                     color: indigo    },
        { label: 'TOTAL RESOURCES', value: ps.totalResources.toLocaleString(),         color: '#10b981' },
        { label: 'TOTAL ISSUES',    value: ps.totalIssues.toLocaleString(),            color: ps.totalIssues > 0 ? '#ef4444' : '#22c55e' },
        { label: 'LATEST SCORE',    value: `${ps.latestScore ?? '—'}%`,               color: ps.latestScore > 80 ? '#22c55e' : ps.latestScore > 50 ? '#eab308' : '#ef4444' },
      ];
      boxes.forEach((b, i) => {
        const bx = 50 + i * (boxW + 10);
        doc.roundedRect(bx, currentY, boxW, 52, 6).fill(slate50);
        doc.moveTo(bx, currentY).lineTo(bx + boxW, currentY).strokeColor(b.color).lineWidth(2.5).stroke();
        doc.fontSize(18).fillColor(b.color).text(b.value, bx + 8, currentY + 12, { width: boxW - 16 });
        doc.fontSize(7).fillColor(slate600).text(b.label, bx + 8, currentY + 36, { width: boxW - 16 });
      });
      currentY += 62;

      // Severity summary row
      const sevItems = [
        { label: 'Critical', value: ps.totalCritical, color: '#dc2626' },
        { label: 'High',     value: ps.totalHigh,     color: '#ea580c' },
        { label: 'Medium',   value: ps.totalMedium,   color: '#ca8a04' },
      ];
      doc.roundedRect(50, currentY, doc.page.width - 100, 40, 6).fill(slate50);
      doc.fontSize(8).fillColor(slate600).text('Severity Breakdown (cumulative across all scans):', 62, currentY + 8);
      let sx = 62;
      sevItems.forEach(sv => {
        const label = `${sv.label}: ${sv.value.toLocaleString()}`;
        doc.fontSize(10).fillColor(sv.color).text(label, sx, currentY + 22);
        sx += doc.widthOfString(label) + 40;
      });
      currentY += 52;

      // Mini bar chart drawn with PDFKit primitives
      const chartTitle = `Vulnerability Breakdown`;
      doc.fontSize(10).fillColor(slate800).text(chartTitle, 50, currentY);
      currentY += 18;

      const chartH = 80;
      const chartW = doc.page.width - 100;
      const maxV   = Math.max(ps.totalCritical, ps.totalHigh, ps.totalMedium, 1);
      const bars   = [
        { label: 'Critical', value: ps.totalCritical, color: '#dc2626' },
        { label: 'High',     value: ps.totalHigh,     color: '#ea580c' },
        { label: 'Medium',   value: ps.totalMedium,   color: '#ca8a04' },
      ];
      const barW   = 40;
      const gap    = (chartW - bars.length * barW) / (bars.length + 1);

      // Axis
      doc.moveTo(50, currentY).lineTo(50, currentY + chartH).strokeColor(slate200).lineWidth(1).stroke();
      doc.moveTo(50, currentY + chartH).lineTo(50 + chartW, currentY + chartH).strokeColor(slate200).lineWidth(1).stroke();

      bars.forEach((b, i) => {
        const bx = 50 + gap + i * (barW + gap);
        const bh = maxV > 0 ? (b.value / maxV) * (chartH - 10) : 0;
        const by = currentY + chartH - bh;

        doc.roundedRect(bx, by, barW, bh, 3).fill(b.color);
        doc.fontSize(8).fillColor(b.color).text(b.value.toLocaleString(), bx + barW / 2 - 10, by - 12, { width: barW + 20, align: 'center' });
        doc.fontSize(7).fillColor(slate600).text(b.label, bx + barW / 2 - 12, currentY + chartH + 4, { width: barW + 24, align: 'center' });
      });

      currentY += chartH + 28;

      // Divider before vulnerability findings
      doc.moveTo(50, currentY).lineTo(doc.page.width - 50, currentY).strokeColor(slate200).lineWidth(1).stroke();
      currentY += 16;
    } else {
      // ── SUMMARY BOX (fallback – Dashboard report style) ─────────────────
      const score     = scanData.score || 0;
      const vulnCount = scanData.vulnerabilities?.length || 0;
      const scanned   = scanData.scanned || 0;

      doc.roundedRect(50, currentY, doc.page.width - 100, 80, 8).fill(slate800);
      doc.fontSize(26).fillColor(score > 80 ? '#22c55e' : score > 50 ? '#eab308' : '#ef4444')
         .text(`${score}%`, 80, currentY + 15);
      doc.fontSize(8).fillColor('#94a3b8').text('SECURITY SCORE', 80, currentY + 50);

      doc.fontSize(26).fillColor('#ffffff').text(`${vulnCount}`, 230, currentY + 15);
      doc.fontSize(8).fillColor('#94a3b8').text('VULNERABILITIES', 230, currentY + 50);

      doc.fontSize(26).fillColor('#ffffff').text(`${scanned}`, 420, currentY + 15);
      doc.fontSize(8).fillColor('#94a3b8').text('RESOURCES SCANNED', 420, currentY + 50);

      currentY += 96;
    }

    // ── FINDINGS TABLES BY SERVICE ────────────────────────────────────────
    const vulnerabilities = scanData.vulnerabilities || [];
    if (vulnerabilities.length > 0) {
      if (currentY > doc.page.height - 140) { doc.addPage(); currentY = 50; }

      doc.fontSize(12).fillColor(slate800).text(`Vulnerability Findings (${vulnerabilities.length})`, 50, currentY);
      doc.moveTo(50, currentY + 16).lineTo(doc.page.width - 50, currentY + 16).strokeColor(slate200).lineWidth(1).stroke();
      currentY += 26;

      // Group by Service and then by Checkpoint
      const serviceGroups = {};
      vulnerabilities.forEach(v => {
        const sName = getServiceName(v.resource);
        if (!serviceGroups[sName]) serviceGroups[sName] = {};
        
        const cpName = getCheckpointName(v.id);
        if (!serviceGroups[sName][cpName]) serviceGroups[sName][cpName] = [];
        serviceGroups[sName][cpName].push(v);
      });

      const sortedServices = Object.keys(serviceGroups).sort();

      for (const sName of sortedServices) {
        if (currentY > doc.page.height - 100) { doc.addPage(); currentY = 50; }

        // Service header
        doc.roundedRect(50, currentY, doc.page.width - 100, 24, 4).fill('#f1f5f9');
        doc.fontSize(10).fillColor(indigo).text(`SERVICE: ${sName.toUpperCase()}`, 60, currentY + 7);
        currentY += 32;

        const checkpointGroups = serviceGroups[sName];
        const sortedCheckpoints = Object.keys(checkpointGroups).sort();

        for (const cpName of sortedCheckpoints) {
          if (currentY > doc.page.height - 100) { doc.addPage(); currentY = 50; }

          // Checkpoint sub-header
          doc.fontSize(9).fillColor(slate800).font('Helvetica-Bold').text(`>> ${cpName}`, 50, currentY);
          doc.font('Helvetica'); // Reset to normal font
          doc.moveTo(50, currentY + 14).lineTo(doc.page.width - 50, currentY + 14).strokeColor(slate200).lineWidth(0.5).stroke();
          currentY += 20;

          // Column headers
          doc.fontSize(7).fillColor(slate600);
          doc.text('SEVERITY', 50,  currentY);
          doc.text('RESOURCE', 110, currentY);
          doc.text('ISSUE DESCRIPTION & REMEDIATION', 280, currentY);
          currentY += 12;

          for (const vuln of checkpointGroups[cpName]) {
            const issueText = `Issue: ${vuln.issue || '-'}\nRemediation: ${vuln.remediation || '-'}`;
            const issueH = doc.heightOfString(issueText, { width: 270, fontSize: 7.5 });
            
            // Check if room for at least one info block
            if (currentY + issueH + 10 > doc.page.height - 60) {
              doc.addPage();
              currentY = 50;
              // Re-draw headers on new page
              doc.fontSize(7).fillColor(slate600);
              doc.text('SEVERITY', 50,  currentY);
              doc.text('RESOURCE', 110, currentY);
              doc.text('ISSUE DESCRIPTION & REMEDIATION', 280, currentY);
              currentY += 12;
            }

            const sevColor = vuln.severity === 'Critical' ? '#dc2626'
                           : vuln.severity === 'High'     ? '#ea580c'
                           : vuln.severity === 'Medium'   ? '#ca8a04' : '#2563eb';

            doc.fontSize(7.5).fillColor(sevColor).text(vuln.severity || '-', 50,  currentY, { width: 55 });
            doc.fontSize(7.5).fillColor(slate800).text(vuln.resource || '-', 110, currentY, { width: 160 });
            doc.fontSize(7.5).fillColor(slate600).text(issueText, 280, currentY, { width: 270, lineGap: 1 });

            currentY += Math.max(issueH, 15) + 12;
            doc.moveTo(50, currentY - 6).lineTo(doc.page.width - 50, currentY - 6).strokeColor(slate100).lineWidth(0.3).stroke();
          }
          currentY += 10;
        }
        currentY += 15;
      }
    } else {
      if (currentY > doc.page.height - 60) { doc.addPage(); currentY = 50; }
      doc.fontSize(13).fillColor('#16a34a').text('No vulnerabilities found. Your infrastructure looks secure! ✓', 50, currentY);
    }

    // ── FOOTER (all pages) ─────────────────────────────────────────────
    const range = doc.bufferedPageRange();
    for (let i = 0; i < range.count; i++) {
      doc.switchToPage(i);
      doc.fontSize(7).fillColor('#94a3b8')
         .text(
           `AuditScope — Automated Cloud Security Platform  |  Page ${i + 1} of ${range.count}  |  Confidential`,
           50, doc.page.height - 38,
           { align: 'center', width: doc.page.width - 100 }
         );
    }

    doc.end();
  });
}

// POST /api/reports/download — generates and returns the PDF directly
router.post('/download', async (req, res) => {
  try {
    const { scanData, selectedServices } = req.body;

    if (!scanData) {
      return res.status(400).json({ error: 'scanData is required in the request body.' });
    }

    if (selectedServices && !selectedServices.includes('ALL')) {
      scanData.vulnerabilities = scanData.vulnerabilities.filter(v => 
        selectedServices.includes(getServiceName(v.resource))
      );
      scanData.score = scanData.score; // Or recalculate score if necessary
      scanData.scanned = new Set(scanData.vulnerabilities.map(v => v.resource)).size;
    }

    const user = await prisma.user.findUnique({ where: { id: req.user.userId } });
    if (!user) return res.status(404).json({ error: 'User not found.' });

    const projectId = scanData.projectId || scanData.provider?.toUpperCase() || 'Cloud Project';

    const pdfBuffer = await generatePDF(scanData, user.name || user.email, projectId);

    const filename = `AuditScope_Report_${new Date().toISOString().slice(0, 10)}.pdf`;

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', pdfBuffer.length);
    res.send(pdfBuffer);

    console.log(`[Report] PDF downloaded by ${user.email}`);

  } catch (error) {
    console.error('[Report] Error generating report:', error);
    res.status(500).json({ error: error.message || 'Failed to generate report.' });
  }
});

// POST /api/reports/send — generates PDF and securely emails it via Nodemailer
router.post('/send', async (req, res) => {
  try {
    const { scanData, recipientEmail, selectedServices, sendPdf, sendExcel } = req.body;

    if (!scanData) {
      return res.status(400).json({ error: 'scanData is required in the request body.' });
    }
    if (!recipientEmail) {
      return res.status(400).json({ error: 'recipientEmail is required.' });
    }

    if (selectedServices && !selectedServices.includes('ALL')) {
      scanData.vulnerabilities = scanData.vulnerabilities.filter(v => 
        selectedServices.includes(getServiceName(v.resource))
      );
      scanData.scanned = new Set(scanData.vulnerabilities.map(v => v.resource)).size;
    }

    const user = await prisma.user.findUnique({ where: { id: req.user.userId } });
    if (!user) return res.status(404).json({ error: 'User not found.' });

    const projectId = scanData.projectId || scanData.provider?.toUpperCase() || 'Cloud Project';

    const emailAttachments = [];

    if (sendPdf !== false) {
      const pdfBuffer = await generatePDF(scanData, user.name || user.email, projectId);
      emailAttachments.push({
        filename: `AuditScope_Report_${new Date().toISOString().slice(0, 10)}.pdf`,
        content: pdfBuffer,
        contentType: 'application/pdf'
      });
    }

    if (sendExcel === true) {
      const projectName = scanData.projectName || scanData.provider || 'Security Audit';
      const excelBuffer = await generateExcelReport(scanData, projectName);
      emailAttachments.push({
        filename: `Security_Audit_${projectName.replace(/\s+/g, '_')}_${new Date().toISOString().slice(0, 10)}.xlsx`,
        content: excelBuffer,
        contentType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      });
    }

    if (emailAttachments.length === 0) {
      return res.status(400).json({ error: 'No report formats selected.' });
    }

    if (!process.env.SMTP_USER || process.env.SMTP_USER === 'your-email@gmail.com') {
      console.log('--- DEVELOPMENT MODE: SMTP NOT CONFIGURED ---');
      console.log(`Simulating Report Email to ${recipientEmail} with ${emailAttachments.length} attachments`);
      console.log('---------------------------------------------');
      return res.json({ success: true, message: `Report emailed to ${recipientEmail} (Simulated - SMTP not configured)` });
    }

    await transporter.sendMail({
      from: `"AuditScope Security" <${process.env.SMTP_USER}>`,
      to: recipientEmail,
      subject: `Confidential Security Audit Report — ${projectId}`,
      html: `
        <div style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; max-width: 650px; margin: 0 auto; padding: 30px; border: 1px solid #e2e8f0; border-radius: 8px; color: #334155;">
          <h2 style="color: #0f172a; border-bottom: 2px solid #06b6d4; padding-bottom: 10px; margin-bottom: 20px;">Confidential Security Audit Report</h2>
          <p style="font-size: 16px; line-height: 1.6;">Dear Stakeholder,</p>
          <p style="font-size: 16px; line-height: 1.6;">Please find the attached comprehensive security audit report detailing the vulnerability posture and infrastructure analysis for the project: <strong style="color: #0f172a;">${projectId}</strong>.</p>
          <p style="font-size: 16px; line-height: 1.6;">This automated assessment evaluates identity management, network configurations, compute environments, and storage isolation against established cloud benchmarking standards.</p>
          
          <table style="width: 100%; margin: 25px 0; border-collapse: collapse;">
            <tbody>
              <tr>
                <td style="padding: 12px; border: 1px solid #e2e8f0; font-weight: bold; width: 40%; background-color: #f8fafc;">Aggregate Safety Score</td>
                <td style="padding: 12px; border: 1px solid #e2e8f0; font-weight: bold; color: ${scanData.score > 80 ? '#16a34a' : scanData.score > 50 ? '#ca8a04' : '#dc2626'};">${scanData.score}%</td>
              </tr>
              <tr>
                <td style="padding: 12px; border: 1px solid #e2e8f0; font-weight: bold; background-color: #f8fafc;">Total Vulnerabilities Identified</td>
                <td style="padding: 12px; border: 1px solid #e2e8f0;">${scanData.vulnerabilities?.length || 0}</td>
              </tr>
              <tr>
                <td style="padding: 12px; border: 1px solid #e2e8f0; font-weight: bold; background-color: #f8fafc;">Total Infrastructure Entities Scanned</td>
                <td style="padding: 12px; border: 1px solid #e2e8f0;">${scanData.scanned || 0}</td>
              </tr>
            </tbody>
          </table>

          <p style="font-size: 14px; line-height: 1.6; color: #64748b;">It is highly recommended that your engineering and security teams review the attached PDF payload for precise remediation directives.</p>
          <p style="font-size: 14px; line-height: 1.6; color: #64748b; margin-top: 30px;">Regards,<br><strong style="color: #0f172a;">AuditScope Automated Systems</strong><br><em>Do not reply to this automated message.</em></p>
        </div>
      `,
      attachments: emailAttachments
    });

    console.log(`[Report] Report emailed successfully to ${recipientEmail}`);
    res.json({ success: true, message: `Report emailed successfully to ${recipientEmail}` });

  } catch (error) {
    console.error('[Report] Error emailing report:', error);
    res.status(500).json({ error: error.message || 'Failed to email report due to internal or SMTP error.' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/reports/project-summary
// Generates a clean one-page PDF of ONLY what is displayed on ProjectDetailsPage:
// project name, provider, created date, total scans, latest score,
// total resources, total issues, and the severity bar chart.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/project-summary', async (req, res) => {
  try {
    const {
      projectName,
      projectId,
      provider,
      createdAt,
      totalScans,
      latestScore,
      totalResources,
      totalIssues,
      totalCritical,
      totalHigh,
      totalMedium,
    } = req.body;

    if (!projectName) {
      return res.status(400).json({ error: 'projectName is required.' });
    }

    const user = await prisma.user.findUnique({ where: { id: req.user.userId } });
    if (!user) return res.status(404).json({ error: 'User not found.' });

    const doc    = new PDFDocument({ margin: 50, size: 'A4', bufferPages: true });
    const chunks = [];
    doc.on('data', c => chunks.push(c));

    const pdfBuf = await new Promise((resolve, reject) => {
      doc.on('end',   () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);

      const W        = doc.page.width;   // 595.28
      const indigo   = '#4f46e5';
      const dark     = '#0f172a';
      const slate50  = '#f8fafc';
      const slate100 = '#f1f5f9';
      const slate200 = '#e2e8f0';
      const slate500 = '#64748b';
      const slate700 = '#334155';
      const slate800 = '#1e293b';

      // Short single-word provider labels — prevents chip text wrapping
      const provShort = {
        gcp:   'GCP',
        aws:   'AWS',
        azure: 'Azure',
      }[provider?.toLowerCase()] || (provider || 'Cloud').toUpperCase();

      // Full provider label for info block
      const provFull = {
        gcp:   'Google Cloud Platform',
        aws:   'Amazon Web Services',
        azure: 'Microsoft Azure',
      }[provider?.toLowerCase()] || (provider || 'Cloud').toUpperCase();

      const scoreNum = latestScore ?? 0;
      const scoreCol = scoreNum > 80 ? '#16a34a' : scoreNum > 50 ? '#ca8a04' : '#dc2626';

      // ── HEADER BAND ────────────────────────────────────────────────
      doc.rect(0, 0, W, 88).fill(dark);

      doc.fontSize(20).fillColor('#ffffff').text('Audit', 50, 26, { continued: true });
      doc.fillColor(indigo).text('Scope');
      doc.fontSize(9).fillColor('#94a3b8').text('Project Summary Report', 50, 52);

      // Generated by (bottom-right of header)
      doc.fontSize(7.5).fillColor('#64748b')
         .text(`Generated: ${new Date().toLocaleString()}  |  By: ${user.name || user.email}`,
               50, 70, { width: W - 100, align: 'right' });

      // Provider badge top-right (short label, fixed 52px wide so it never wraps)
      doc.roundedRect(W - 92, 24, 42, 20, 4).fill('rgba(99,102,241,0.35)');
      doc.fontSize(8.5).fillColor('#c7d2fe')
         .text(provShort, W - 92, 30, { width: 42, align: 'center' });

      let y = 104;

      // ── PROJECT INFO BLOCK ──────────────────────────────────────────
      // Height 72: enough for name (up to 2 lines) + provider chip
      doc.roundedRect(50, y, W - 100, 72, 8).fill(slate100);

      // Project name — constrained width so it doesn't overlap Right column
      doc.fontSize(14).fillColor(slate800)
         .text(projectName, 64, y + 12, { width: W - 260, lineGap: 2 });

      // Provider chip (single short label, fixed 70px wide)
      doc.roundedRect(64, y + 48, 70, 16, 8).fill(indigo + '25');
      doc.fontSize(7.5).fillColor(indigo)
         .text(provFull, 64, y + 52, { width: 70, align: 'center' });

      // Right column: Project ID + Created
      const rx = W - 190;
      doc.fontSize(7).fillColor(slate500).text('PROJECT ID', rx, y + 10);
      doc.fontSize(8).fillColor(slate700)
         .text(String(projectId || projectName).substring(0, 28), rx, y + 21, { width: 140 });
      doc.fontSize(7).fillColor(slate500).text('CREATED', rx, y + 44);
      const dateStr = createdAt
        ? new Date(createdAt).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
        : '—';
      doc.fontSize(8).fillColor(slate700).text(dateStr, rx, y + 55, { width: 140 });

      y += 84;

      // ── SUMMARY METRICS ─────────────────────────────────────────────
      doc.fontSize(8).fillColor(slate500)
         .text('SUMMARY METRICS', 50, y, { characterSpacing: 1.5 });
      doc.moveTo(50, y + 13).lineTo(W - 50, y + 13)
         .strokeColor(slate200).lineWidth(0.7).stroke();
      y += 20;

      // 4 stat cards — 62px tall, 4px gap
      const stats = [
        { label: 'TOTAL SCANS',      value: String(totalScans ?? 0),                 color: indigo,    bg: '#eef2ff' },
        { label: 'LATEST SCORE',     value: `${scoreNum}%`,                          color: scoreCol,  bg: slate50   },
        { label: 'LATEST RESOURCES', value: (totalResources ?? 0).toLocaleString(),  color: '#059669', bg: '#ecfdf5' },
        { label: 'ACTIVE ISSUES',    value: (totalIssues    ?? 0).toLocaleString(),  color: (totalIssues ?? 0) > 0 ? '#dc2626' : '#059669', bg: (totalIssues ?? 0) > 0 ? '#fef2f2' : '#ecfdf5' },
      ];
      const cardW = (W - 100 - 18) / 4; // 3 × 6px gap
      const cardH = 62;

      stats.forEach((s, i) => {
        const bx = 50 + i * (cardW + 6);
        doc.roundedRect(bx, y, cardW, cardH, 6).fill(s.bg);
        doc.roundedRect(bx, y, cardW, 3, 2).fill(s.color);          // top bar
        // Value — centred vertically: top=12, fontSize=20 ≈ 24px tall → fits in 62px card
        doc.fontSize(20).fillColor(s.color)
           .text(s.value, bx + 6, y + 14, { width: cardW - 12, align: 'center' });
        // Label — 44px from top so it's below value
        doc.fontSize(6.5).fillColor(slate500)
           .text(s.label, bx + 4, y + 46, { width: cardW - 8, align: 'center', characterSpacing: 0.4 });
      });

      y += cardH + 18;

      // ── VULNERABILITY BREAKDOWN ──────────────────────────────────────
      doc.fontSize(8).fillColor(slate500)
         .text('VULNERABILITY BREAKDOWN', 50, y, { characterSpacing: 1.5, continued: true });
      doc.fontSize(7.5).fillColor('#94a3b8')
         .text('  — based on the latest scan', { characterSpacing: 0 });
      doc.moveTo(50, y + 13).lineTo(W - 50, y + 13)
         .strokeColor(slate200).lineWidth(0.7).stroke();
      y += 20;

      const sevItems = [
        { label: 'Critical', value: totalCritical ?? 0, color: '#dc2626', bg: '#fef2f2' },
        { label: 'High',     value: totalHigh     ?? 0, color: '#ea580c', bg: '#fff7ed' },
        { label: 'Medium',   value: totalMedium   ?? 0, color: '#ca8a04', bg: '#fefce8' },
      ];
      const sevChipW = 110, sevChipH = 52, sevGap = 14;

      sevItems.forEach((sv, i) => {
        const cx = 50 + i * (sevChipW + sevGap);
        doc.roundedRect(cx, y, sevChipW, sevChipH, 6).fill(sv.bg);
        doc.roundedRect(cx, y, sevChipW, 3, 2).fill(sv.color);
        doc.fontSize(18).fillColor(sv.color).text(sv.value.toLocaleString(), cx, y + 10, { width: sevChipW, align: 'center' });
        doc.fontSize(8).fillColor(sv.color).text(sv.label, cx, y + 36, { width: sevChipW, align: 'center' });
      });
      y += sevChipH + 28;

      // ── SECURITY SCORE TREND LINE CHART ─────────────────────────────
      doc.fontSize(8).fillColor(slate500).text('HISTORICAL SECURITY SCORE TREND', 50, y, { characterSpacing: 1 });
      doc.moveTo(50, y + 12).lineTo(W - 50, y + 12).strokeColor(slate200).lineWidth(0.5).stroke();
      y += 24;

      const chH = 100, chW = W - 140, chL = 80;
      doc.roundedRect(50, y - 10, W - 100, chH + 30, 8).fill('#fafafa');
      
      for (let i = 0; i <= 4; i++) {
        const gy = y + chH - (i / 4) * chH;
        doc.moveTo(chL, gy).lineTo(chL + chW, gy).strokeColor(slate200).lineWidth(0.5).stroke();
        doc.fontSize(7).fillColor(slate500).text(`${i * 25}%`, chL - 25, gy - 3);
      }

      const history = req.body.scoreHistory || [];
      if (history.length > 1) {
        doc.strokeColor(indigo).lineWidth(2);
        history.forEach((pt, i) => {
          const px = chL + (i / (history.length - 1)) * chW;
          const py = y + chH - (pt.value / 100) * chH;
          if (i === 0) doc.moveTo(px, py); else doc.lineTo(px, py);
        });
        doc.stroke();
      }
      
      history.forEach((pt, i) => {
        const px = chL + (i / Math.max(history.length - 1, 1)) * chW;
        const py = y + chH - (pt.value / 100) * chH;
        doc.circle(px, py, 3).fill(indigo);
        if (i === 0 || i === history.length - 1 || history.length < 8) {
          doc.fontSize(6).fillColor(dark).text(`${pt.value}%`, px - 10, py - 10, { width: 20, align: 'center' });
          doc.fontSize(6).fillColor(slate500).text(pt.label, px - 15, y + chH + 5, { width: 30, align: 'center' });
        }
      });
      y += chH + 45;

      // ── RECENT SCAN RESULTS ─────────────────────────────────────────
      const recent = req.body.recentScans || [];
      if (recent.length > 0) {
        doc.fontSize(8).fillColor(slate500).text('RECENT PROJECT SCAN LOGS', 50, y, { characterSpacing: 1 });
        doc.moveTo(50, y + 12).lineTo(W - 50, y + 12).strokeColor(slate200).lineWidth(0.5).stroke();
        y += 22;

        recent.forEach((s, i) => {
          if (y > doc.page.height - 80) { doc.addPage(); y = 50; }
          doc.roundedRect(50, y, W - 100, 32, 4).fill(slate50);
          doc.fontSize(10).fillColor(s.score > 80 ? '#16a34a' : '#ef4444').text(`${s.score}%`, 64, y + 10, { width: 30, fontWeight: 700 });
          doc.fontSize(8).fillColor(dark).text(`Scan on ${s.date} at ${s.time}`, 100, y + 11);
          doc.fontSize(7.5).fillColor('#dc2626').text(`${s.critical} Critical`, W - 180, y + 11);
          doc.fontSize(7.5).fillColor('#f97316').text(`${s.high} High`, W - 120, y + 11);
          y += 38;
        });
      }

      // ── ALL CLEAR NOTE ───────────────────────────────────────────────
      if ((totalIssues ?? 0) === 0) {
        if (y > doc.page.height - 80) { doc.addPage(); y = 50; }
        doc.roundedRect(50, y, W - 100, 30, 6).fill('#ecfdf5');
        doc.fontSize(10).fillColor('#16a34a')
           .text('✓  No vulnerabilities found across all scans. Infrastructure looks secure!',
                 64, y + 9, { width: W - 128 });
        y += 42;
      }

      // ── FOOTER ───────────────────────────────────────────────────────
      const footerY = doc.page.height - 34;
      doc.moveTo(50, footerY - 7).lineTo(W - 50, footerY - 7)
         .strokeColor(slate200).lineWidth(0.5).stroke();
      doc.fontSize(7.5).fillColor(slate500)
         .text('AuditScope — Automated Cloud Security Platform  |  Confidential',
               50, footerY, { align: 'center', width: W - 100 });

      doc.end();
    });

    const filename = `AuditScope_${projectName.replace(/\s+/g, '_')}_Summary_${new Date().toISOString().slice(0, 10)}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', pdfBuf.length);
    res.send(pdfBuf);

    console.log(`[Report] Project summary PDF downloaded for "${projectName}" by ${user.email}`);

  } catch (err) {
    console.error('[Report] project-summary error:', err);
    res.status(500).json({ error: err.message || 'Failed to generate project summary PDF.' });
  }
});

/**
 * Endpoint for exporting scan history as Excel
 */
router.post('/export-excel', authenticateToken, async (req, res) => {
  try {
    const { scanId, scanData } = req.body;
    let scan;
    let projectName = 'Security Audit';

    if (scanId) {
      scan = await prisma.scanHistory.findUnique({
        where: { id: scanId },
        include: { project: true }
      });
      if (!scan) return res.status(404).json({ error: 'Scan record not found in database.' });
      projectName = scan.project ? scan.project.name : 'Security Audit';
    } else if (scanData) {
      // Allow exporting live results that haven't reach DB yet
      scan = scanData;
      projectName = scanData.projectName || scanData.provider || 'Security Audit';
    } else {
      return res.status(400).json({ error: 'Either scanId or scanData is required.' });
    }

    const excelBuffer = await generateExcelReport(scan, projectName);

    const filename = `Security_Audit_${projectName.replace(/\s+/g, '_')}_${new Date().toISOString().slice(0, 10)}.xlsx`;

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', excelBuffer.length);
    res.send(excelBuffer);

    console.log(`[Report] Excel report downloaded for "${projectName}" by ${req.user.email}`);

  } catch (err) {
    console.error('[Report] export-excel error:', err);
    res.status(500).json({ error: 'Failed to generate Excel report: ' + err.message });
  }
});

router.generatePDF = generatePDF;
module.exports = router;
