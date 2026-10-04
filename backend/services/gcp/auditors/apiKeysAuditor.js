const { google } = require('googleapis');

/**
 * Audits GCP API Keys configurations according to the checklist.
 * 
 * @param {Object} googleAuthClient - The authorized googleapis client
 * @param {string} projectId - The GCP Project ID
 */
const auditApiKeys = async (googleAuthClient, projectId) => {
  const findings = [];
  let scannedCount = 0;

  try {
    console.log(`[API Keys] Starting API Keys audit for project: ${projectId}`);
    
    // Initialize googleapis resources
    const apikeys = google.apikeys({ version: 'v2', auth: googleAuthClient });

    let keysResponse;
    try {
      keysResponse = await apikeys.projects.locations.keys.list({
        parent: `projects/${projectId}/locations/global`
      });
    } catch (apiErr) {
       console.warn("[API Keys] Failed to list API keys or API not enabled:", apiErr.message);
       return { findings, scannedCount };
    }

    const keys = keysResponse.data.keys || [];
    scannedCount += keys.length;

    for (const key of keys) {
      const keyId = key.displayName || key.uid || key.name.split('/').pop();
      const shortId = key.uid ? key.uid.substring(0, 8) : keyId.substring(0, 8);

      // Check 7 & 8: API Key Restrictions
      if (!key.restrictions || Object.keys(key.restrictions).length === 0) {
        findings.push({
          id: `GCP-APIKEY-UNRESTRICTED-${shortId}`,
          severity: 'Critical',
          resource: `API Key (${keyId})`,
          issue: `API Key has no application or API restrictions.`,
          remediation: `Configure application restrictions (e.g., HTTP referrers, IP addresses) and restrict the key to only the APIs it needs to access.`
        });
      } else {
        // Has restrictions, but let's check if API restrictions specifically are applied
        if (!key.restrictions.apiTargets || key.restrictions.apiTargets.length === 0) {
           findings.push({
            id: `GCP-APIKEY-NO-API-RESTRICTION-${shortId}`,
            severity: 'High',
            resource: `API Key (${keyId})`,
            issue: `API Key has application restrictions but is not restricted to specific APIs.`,
            remediation: `Limit the API key to explicitly required APIs.`
          });
        }
      }

      // Check 9: API Key age (Rotation)
      if (key.createTime) {
        const createTime = new Date(key.createTime);
        const now = new Date();
        const diffDays = Math.floor((now - createTime) / (1000 * 60 * 60 * 24));
        
        if (diffDays > 90) {
          findings.push({
            id: `GCP-APIKEY-ROTATION-${shortId}`,
            severity: 'Medium',
            resource: `API Key (${keyId})`,
            issue: `API Key is ${diffDays} days old. It has not been rotated in the last 90 days.`,
            remediation: `Rotate API Keys every 90 days by creating a new key, migrating applications, and deleting the old key.`
          });
        }
      }
    }

    return { findings, scannedCount };

  } catch (error) {
    console.error("[API Keys] Critical error during API Keys audit:", error);
    return { findings: [], scannedCount: 0, error: error.message }; 
  }
};

module.exports = { auditApiKeys };
