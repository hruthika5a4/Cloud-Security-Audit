const { google } = require('googleapis');

/**
 * Audits Cloud SQL instances for security misconfigurations.
 * 
 * @param {Object} googleAuthClient - Authorized googleapis client
 * @param {string} projectId - GCP Project ID
 */
const auditCloudSQL = async (googleAuthClient, projectId) => {
  const findings = [];
  let scannedCount = 0;

  try {
    console.log(`[Cloud SQL] Starting SQL audit for project: ${projectId}`);
    
    const sqlAdmin = google.sqladmin({ version: 'v1beta4', auth: googleAuthClient });

    const response = await sqlAdmin.instances.list({ project: projectId });
    const instances = response.data.items || [];
    scannedCount = instances.length;

    for (const instance of instances) {
      const config = instance.settings;
      if (!config) continue;

      // 1. Check Require SSL
      const requireSsl = config.ipConfiguration?.requireSsl;
      if (!requireSsl) {
        findings.push({
          id: `GCP-SQL-SSL-${instance.name.substring(0, 8)}`,
          severity: 'Critical',
          resource: `Cloud SQL Database (${instance.name})`,
          issue: `Incoming connections are NOT required to use SSL.`,
          remediation: `Modify the instance network settings to explicitly require SSL for all incoming connections.`
        });
      }

      // 2. Check for Public IPs and 0.0.0.0/0 Authorized Networks
      if (config.ipConfiguration) {
        const ipAddresses = instance.ipAddresses || [];
        const hasPublicIp = ipAddresses.some(ip => ip.type === 'PRIMARY'); // Typically PRIMARY implies external in Cloud SQL unless Private Services Access is solely used

        if (hasPublicIp) {
           findings.push({
            id: `GCP-SQL-PUBLIC-${instance.name.substring(0, 8)}`,
            severity: 'High',
            resource: `Cloud SQL Database (${instance.name})`,
            issue: `Database Instance possesses a Public IP address.`,
            remediation: `Configure the instance to use Private IP only for internal VPC communication if public access isn't strictly necessary.`
          });
        }

        const authNetworks = config.ipConfiguration.authorizedNetworks || [];
        const allowsAllAccess = authNetworks.some(net => net.value === '0.0.0.0/0' || net.value === '::/0');
        
        if (allowsAllAccess) {
          findings.push({
            id: `GCP-SQL-OPEN-${instance.name.substring(0, 8)}`,
            severity: 'Critical',
            resource: `Cloud SQL Database (${instance.name})`,
            issue: `Authorized networks explicitly whitelist all public IPs (0.0.0.0/0).`,
            remediation: `Remove 0.0.0.0/0 from Authorized Networks. Restrict access to specific, known IP ranges or utilize Cloud SQL Proxy.`
          });
        }
      }

      // 3. Check Automated Backups & PITR
      const backupConfiguration = config.backupConfiguration;
      if (!backupConfiguration || !backupConfiguration.enabled) {
        findings.push({
          id: `GCP-SQL-BACKUP-${instance.name.substring(0, 8)}`,
          severity: 'High',
          resource: `Cloud SQL Database (${instance.name})`,
          issue: `Automated Backups are NOT configured.`,
          remediation: `Enable automated daily backups to protect against data loss.`
        });
      } else if (!backupConfiguration.pointInTimeRecoveryEnabled) {
         findings.push({
          id: `GCP-SQL-PITR-${instance.name.substring(0, 8)}`,
          severity: 'Medium',
          resource: `Cloud SQL Database (${instance.name})`,
          issue: `Point-in-Time Recovery (PITR) is NOT enabled.`,
          remediation: `Enable point-in-time recovery to allow restoring your database natively from a specific operational state.`
        });
      }

      // 4. Database Flags Enforcement
      const dbVersion = instance.databaseVersion || '';
      const flags = config.databaseFlags || [];
      const getFlag = (flagName) => flags.find(f => f.name === flagName)?.value;

      if (dbVersion.includes('POSTGRES')) {
        const requiredFlags = [
          { name: 'log_checkpoints', expected: 'on', severity: 'Medium' },
          { name: 'log_connections', expected: 'on', severity: 'Medium' },
          { name: 'log_disconnections', expected: 'on', severity: 'Medium' },
          { name: 'log_lock_waits', expected: 'on', severity: 'Medium' },
          { name: 'log_min_messages', expected: 'warning', altExpected: 'error', severity: 'Medium' },
          { name: 'log_temp_files', expected: '0', severity: 'Low' },
          { name: 'log_min_duration_statement', expected: '-1', severity: 'Low' }
        ];
        for (const rf of requiredFlags) {
           const val = getFlag(rf.name);
           if (val !== rf.expected && val !== rf.altExpected) {
             findings.push({
                id: `GCP-SQL-PG-FLAG-${rf.name}-${instance.name.substring(0, 8)}`,
                severity: rf.severity,
                resource: `Cloud SQL Postgres (${instance.name})`,
                issue: `Database flag '${rf.name}' is set to '${val || 'Not Set'}', expected '${rf.expected}'.`,
                remediation: `Configure the database flag '${rf.name}' to enforce CIS benchmark baseline auditing protocols.`
             });
           }
        }
      } else if (dbVersion.includes('MYSQL')) {
         const localInfile = getFlag('local_infile');
         if (localInfile !== 'off') {
             findings.push({
                id: `GCP-SQL-MY-FLAG-INFILE-${instance.name.substring(0, 8)}`,
                severity: 'High',
                resource: `Cloud SQL MySQL (${instance.name})`,
                issue: `Database flag 'local_infile' is NOT 'off'.`,
                remediation: `Set 'local_infile' to off to prevent arbitrary local files from being imported into the database maliciously.`
             });
         }
         const skipShowDatabase = getFlag('skip_show_database');
         if (skipShowDatabase !== 'on') {
             findings.push({
                id: `GCP-SQL-MY-FLAG-SHOWDB-${instance.name.substring(0, 8)}`,
                severity: 'Low',
                resource: `Cloud SQL MySQL (${instance.name})`,
                issue: `Database flag 'skip_show_database' is NOT 'on'.`,
                remediation: `Set 'skip_show_database' to on to prevent users from seeing databases they do not hold privileges for.`
             });
         }
      } else if (dbVersion.includes('SQLSERVER')) {
         const crossDbChaining = getFlag('cross db ownership chaining');
         if (crossDbChaining === 'on') {
             findings.push({
                id: `GCP-SQL-MS-FLAG-CHAIN-${instance.name.substring(0, 8)}`,
                severity: 'High',
                resource: `Cloud SQL SQLServer (${instance.name})`,
                issue: `Database flag 'cross db ownership chaining' is enabled.`,
                remediation: `Disable cross db ownership chaining to restrict privileges boundary scaling across segmented databases.`
             });
         }
         const containedDbAuth = getFlag('contained database authentication');
         if (containedDbAuth === 'on') {
             findings.push({
                id: `GCP-SQL-MS-FLAG-AUTH-${instance.name.substring(0, 8)}`,
                severity: 'Medium',
                resource: `Cloud SQL SQLServer (${instance.name})`,
                issue: `Database flag 'contained database authentication' is enabled.`,
                remediation: `Disable contained database authentication. It breaks the centralized isolation and lifecycle controls of SQL Server IAM.`
             });
         }
      }
    }

    return { findings, scannedCount };

  } catch (error) {
    console.error("[Cloud SQL] Error during SQL audit:", error);
    return { findings: [], scannedCount: 0, error: error.message }; 
  }
};

module.exports = { auditCloudSQL };
