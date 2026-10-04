const { google } = require('googleapis');

/**
 * Audits GCP Logging, Monitoring, and Observability configurations.
 * 
 * @param {Object} googleAuthClient - The authorized googleapis client
 * @param {string} projectId - The GCP Project ID
 */
const auditLogging = async (googleAuthClient, projectId) => {
  const findings = [];
  let scannedCount = 0;

  try {
    console.log(`[Logging] Starting Logging & Observability audit for project: ${projectId}`);
    
    const logging = google.logging({ version: 'v2', auth: googleAuthClient });
    const cloudresourcemanager = google.cloudresourcemanager({ version: 'v1', auth: googleAuthClient });
    const storage = google.storage({ version: 'v1', auth: googleAuthClient });
    const serviceusage = google.serviceusage({ version: 'v1', auth: googleAuthClient });
    const accessapproval = google.accessapproval({ version: 'v1', auth: googleAuthClient });

    scannedCount++; // general project scan

    // --- 1. Audit Auth/Audit Configs ---
    try {
      const iamPolicyResponse = await cloudresourcemanager.projects.getIamPolicy({
        resource: projectId,
        requestBody: {}
      });
      const policy = iamPolicyResponse.data;
      
      let allServicesAudited = false;
      if (policy.auditConfigs) {
        for (const config of policy.auditConfigs) {
           if (config.service === 'allServices') {
             // ensure it has ADMIN_READ, DATA_READ, and DATA_WRITE
             const logTypes = config.auditLogConfigs ? config.auditLogConfigs.map(c => c.logType) : [];
             if (logTypes.includes('ADMIN_READ') && logTypes.includes('DATA_READ') && logTypes.includes('DATA_WRITE')) {
                allServicesAudited = true;
             }
           }
        }
      }

      if (!allServicesAudited) {
        findings.push({
          id: `GCP-LOG-AUDIT-${projectId.substring(0, 8)}`,
          severity: 'High',
          resource: `Project IAM Audit Settings`,
          issue: `Cloud Audit Logging is not properly configured to capture all log types (ADMIN_READ, DATA_READ, DATA_WRITE) for 'allServices'.`,
          remediation: `Configure Cloud Audit Logs to track all administrative and data access events across all services.`
        });
      }
    } catch(e) { }

    // --- 2 & 3. Logging Sinks & Retention Policies ---
    try {
      const sinksResponse = await logging.projects.sinks.list({ parent: `projects/${projectId}` });
      const sinks = sinksResponse.data.sinks || [];
      scannedCount += sinks.length;
      
      let catchAllSinkExists = false;

      for (const sink of sinks) {
        if (!sink.filter || sink.filter.trim() === '') {
           catchAllSinkExists = true;
        }

        // Check 3: Storage Bucket Locks
        if (sink.destination && sink.destination.startsWith('storage.googleapis.com/')) {
           const bucketName = sink.destination.replace('storage.googleapis.com/', '');
           try {
             const bucketObj = await storage.buckets.get({ bucket: bucketName });
             if (!bucketObj.data.retentionPolicy || !bucketObj.data.retentionPolicy.isLocked) {
                findings.push({
                  id: `GCP-LOG-BUCKET-LOCK-${bucketName.substring(0, 8)}`,
                  severity: 'Medium',
                  resource: `Cloud Storage Sink (${bucketName})`,
                  issue: `Retention policies on the bucket used for exporting logs are not configured with a Bucket Lock.`,
                  remediation: `Configure a retention policy and lock it to prevent log entries from being deleted or modified.`
                });
             }
           } catch(bucketErr) {
             // could be permission error resolving bucket if it's external
           }
        }
      }

      if (sinks.length === 0 || !catchAllSinkExists) {
        findings.push({
          id: `GCP-LOG-SINK-${projectId.substring(0, 8)}`,
          severity: 'Medium',
          resource: `Project Sinks`,
          issue: `Proper 'catch-all' Logging Sinks are not configured to export all log entries.`,
          remediation: `Configure a log sink without exclusionary filters, exporting to an aggregation destination like BigQuery or Cloud Storage.`
        });
      }
    } catch(e) { }

    // --- 4 through 11. Metric Filters ---
    try {
       const metricsResponse = await logging.projects.metrics.list({ parent: `projects/${projectId}` });
       const metrics = metricsResponse.data.metrics || [];
       scannedCount += metrics.length;
       
       const allFilters = metrics.map(m => m.filter ? m.filter.toLowerCase() : '').join(' || ');

       const requiredMetrics = [
         { id: 'OWNERSHIP', keywords: ['resourcemanager.projects.setiampolicy', 'roles/owner'], title: 'Project Ownership Assignments/Changes' },
         { id: 'AUDIT_CFG', keywords: ['auditconfig'], title: 'Audit Configuration Changes' },
         { id: 'CUSTOM_ROLE', keywords: ['iam.roles.create', 'iam.roles.delete', 'iam.roles.update'], title: 'Custom Role Changes' },
         { id: 'FW_RULE', keywords: ['compute.firewalls.insert', 'compute.firewalls.patch', 'compute.firewalls.delete'], title: 'VPC Network Firewall Rule Changes' },
         { id: 'VPC_ROUTE', keywords: ['compute.routes.insert', 'compute.routes.delete'], title: 'VPC Network Route Changes' },
         { id: 'VPC_NET', keywords: ['compute.networks.insert', 'compute.networks.delete'], title: 'VPC Network Changes' },
         { id: 'STORAGE_IAM', keywords: ['storage.setiampermissions'], title: 'Cloud Storage IAM Permission Changes' },
         { id: 'SQL_CFG', keywords: ['cloudsql.instances.update'], title: 'SQL Instance Configuration Changes' }
       ];

       for (const req of requiredMetrics) {
         const hasMetric = req.keywords.some(kw => allFilters.includes(kw));
         if (!hasMetric) {
           findings.push({
              id: `GCP-LOG-METRIC-${req.id}-${projectId.substring(0, 8)}`,
              severity: 'Low',
              resource: `Log Metrics`,
              issue: `Log Metric Filter and Alerts do not exist for ${req.title}.`,
              remediation: `Create a log metric matching the pertinent event logs, and configure a Cloud Monitoring Alert Policy to notify administrators on occurrence.`
           });
         }
       }
    } catch(e) { }

    // --- 13. Cloud Asset Inventory Status ---
    try {
      const suResponse = await serviceusage.services.get({ name: `projects/${projectId}/services/cloudasset.googleapis.com` });
      if (suResponse.data.state !== 'ENABLED') {
         findings.push({
            id: `GCP-OBS-ASSET-${projectId.substring(0, 8)}`,
            severity: 'Low',
            resource: `Cloud Asset Inventory API`,
            issue: `Cloud Asset Inventory is not enabled.`,
            remediation: `Enable the Cloud Asset API to allow historical tracking and monitoring of GCP resource configurations.`
         });
      }
    } catch(e) { }

    // --- 14 & 15. Access Transparency and Approval ---
    try {
      // Access Transparency (Organization level check often)
      const suAssetResponse = await serviceusage.services.get({ name: `projects/${projectId}/services/accesstransparency.googleapis.com` });
      if (suAssetResponse.data.state !== 'ENABLED') {
         findings.push({
            id: `GCP-OBS-TRANSPARENCY-${projectId.substring(0, 8)}`,
            severity: 'Medium',
            resource: `Access Transparency API`,
            issue: `Access Transparency is not enabled.`,
            remediation: `If using GCP Organizations, enable Access Transparency to ensure Google personnel actions on your data are logged.`
         });
      }

      // Access Approval
      const approvalRes = await accessapproval.projects.getAccessApprovalSettings({ name: `projects/${projectId}/accessApprovalSettings` });
      if (!approvalRes.data.enrolledServices || approvalRes.data.enrolledServices.length === 0) {
         findings.push({
            id: `GCP-OBS-APPROVAL-${projectId.substring(0, 8)}`,
            severity: 'Medium',
            resource: `Access Approval Settings`,
            issue: `Access Approval is not enabled or lacks enrolled services.`,
            remediation: `Enable Access Approval to require explicit approval before Google support can access your data.`
         });
      }
    } catch(err) {
      if (err.message.includes('Method not found') || err.code === 403 || err.code === 404) {
          // If we can't check, it's often because it's not enabled or Org is missing
          if (!findings.some(f => f.id.includes('GCP-OBS-TRANSPARENCY'))) {
            findings.push({
              id: `GCP-OBS-TRANSPARENCY-${projectId.substring(0, 8)}`,
              severity: 'Medium',
              resource: `Access Transparency`,
              issue: `Access Transparency is likely not enabled (requires Organization context).`,
              remediation: `Enable Access Transparency at the organization or project level.`
            });
          }
      }
    }

    return { findings, scannedCount };

  } catch (error) {
    console.error("[Logging] Critical error during Logging audit:", error);
    return { findings: [], scannedCount: 0, error: error.message }; 
  }
};

module.exports = { auditLogging };
