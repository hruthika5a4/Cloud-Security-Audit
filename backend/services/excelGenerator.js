const ExcelJS = require('exceljs');

/**
 * Maps finding IDs to Cloud Service Categories
 */
const getCategoryFromId = (id) => {
    if (!id) return 'General';
    const prefix = id.split('-')[1] || '';
    switch (prefix.toUpperCase()) {
        case 'IAM': return 'IAM';
        case 'STORAGE': return 'Storage';
        case 'KMS': return 'KMS';
        case 'SQL': return 'Cloud SQL';
        case 'NET':
        case 'DNS':
        case 'FIREWALL': return 'Networking';
        case 'COMPUTE':
        case 'VM': return 'Compute';
        case 'LOG':
        case 'MONITOR': return 'Logging';
        case 'GKE': return 'GKE';
        case 'CLOUDRUN':
        case 'FUNCTION': return 'Serverless';
        case 'LB': return 'Load Balancers';
        case 'DATAPROC': return 'Dataproc';
        case 'RDS': return 'AWS RDS';
        case 'EKS': return 'AWS EKS';
        default: return 'General';
    }
};

/**
 * Maps finding IDs to human-readable Checkpoint names
 */
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
        'SERVERLESS': 'Check Serverless'
    };

    return mapping[checkType] || `Check: ${checkType}`;
};

/**
 * Generates a styled Excel report from scan data
 * @param {Object} scanData - The scan history record or data object
 * @param {string} projectName - Name of the project
 * @returns {Buffer} - Excel file buffer
 */
const generateExcelReport = async (scanData, projectName) => {
    const workbook = new ExcelJS.Workbook();
    workbook.creator = 'AuditScope';
    workbook.lastModifiedBy = 'AuditScope';
    workbook.created = new Date();
    workbook.modified = new Date();

    // --- 1. Summary Sheet ---
    const summarySheet = workbook.addWorksheet('Summary');
    
    // Styling constants
    const headerFill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFE2E8F0' } };
    const titleFont = { name: 'Arial', size: 16, bold: true, color: { argb: 'FF1E293B' } };
    const labelFont = { name: 'Arial', size: 11, bold: true };

    summarySheet.columns = [
        { header: 'Metric', key: 'metric', width: 30 },
        { header: 'Value', key: 'value', width: 40 }
    ];

    // Add Title
    summarySheet.mergeCells('A1:B1');
    const titleCell = summarySheet.getCell('A1');
    titleCell.value = `Security Audit Summary: ${projectName}`;
    titleCell.font = titleFont;
    titleCell.alignment = { horizontal: 'center' };

    summarySheet.addRow({}); // spacer

    // Add Data
    const vulnerabilities = Array.isArray(scanData.vulnerabilities) 
        ? scanData.vulnerabilities 
        : (typeof scanData.findings === 'string' ? JSON.parse(scanData.findings) : []);

    const metrics = [
        ['Project Name', projectName],
        ['Scan Date', new Date(scanData.createdAt || Date.now()).toLocaleString()],
        ['Overall Security Score', `${scanData.score}%`],
        ['Total Resources Scanned', scanData.scannedResources || scanData.scanned || 0],
        ['', ''],
        ['Critical Vulnerabilities', scanData.criticalCount || vulnerabilities.filter(v => v.severity === 'Critical').length],
        ['High Vulnerabilities', scanData.highCount || vulnerabilities.filter(v => v.severity === 'High').length],
        ['Medium Vulnerabilities', scanData.mediumCount || vulnerabilities.filter(v => v.severity === 'Medium').length],
        ['Low Vulnerabilities', (scanData.lowCount || 0) + vulnerabilities.filter(v => v.severity === 'Low').length]
    ];

    metrics.forEach(m => {
        const row = summarySheet.addRow({ metric: m[0], value: m[1] });
        row.getCell(1).font = labelFont;
    });

    // Formatting
    summarySheet.getRow(1).height = 30;
    summarySheet.getColumn(1).eachCell((cell) => {
        if (cell.value && cell.value !== 'Metric') {
            cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF8FAFC' } };
        }
    });

    // --- 2. Service-Specific Sheets ---
    const findingsByCategory = vulnerabilities.reduce((acc, v) => {
        const category = getCategoryFromId(v.id);
        if (!acc[category]) acc[category] = [];
        acc[category].push(v);
        return acc;
    }, {});

    Object.entries(findingsByCategory).forEach(([category, findings]) => {
        const sheetName = category.substring(0, 30);
        const sheet = workbook.addWorksheet(sheetName);

        sheet.columns = [
            { header: 'Checkpoint / Resource', key: 'resource', width: 45 },
            { header: 'ID', key: 'id', width: 25 },
            { header: 'Severity', key: 'severity', width: 15 },
            { header: 'Issue Description', key: 'issue', width: 60 },
            { header: 'Remediation Step', key: 'remediation', width: 70 }
        ];

        // Style the main header
        sheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
        sheet.getRow(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1E293B' } }; // Dark blue/slate

        // Group findings by Checkpoint Name within the Service
        const checkpoints = findings.reduce((acc, f) => {
            const cpName = getCheckpointName(f.id);
            if (!acc[cpName]) acc[cpName] = [];
            acc[cpName].push(f);
            return acc;
        }, {});

        Object.entries(checkpoints).forEach(([cpName, cpFindings]) => {
            // Add Checkpoint Header Row
            const headerRow = sheet.addRow({ resource: cpName.toUpperCase() });
            headerRow.font = { bold: true, size: 12 };
            headerRow.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF1F5F9' } }; // Light slate background
            headerRow.getCell(1).alignment = { horizontal: 'left' };
            sheet.mergeCells(`A${headerRow.number}:E${headerRow.number}`);

            // Add each finding under this checkpoint
            cpFindings.forEach(f => {
                const row = sheet.addRow({
                    resource: f.resource,
                    id: f.id,
                    severity: f.severity,
                    issue: f.issue,
                    remediation: f.remediation
                });

                // Style severity
                const sevCell = row.getCell(3);
                switch (f.severity) {
                    case 'Critical': sevCell.font = { color: { argb: 'FFFF0000' }, bold: true }; break;
                    case 'High': sevCell.font = { color: { argb: 'FFFF8C00' }, bold: true }; break;
                    case 'Medium': sevCell.font = { color: { argb: 'FFFFA500' }, bold: true }; break;
                    case 'Low': sevCell.font = { color: { argb: 'FF008000' }, bold: true }; break;
                }

                row.alignment = { vertical: 'top', wrapText: true };
            });

            // Add small spacer row
            sheet.addRow({});
        });
    });

    return await workbook.xlsx.writeBuffer();
};

module.exports = { generateExcelReport };
