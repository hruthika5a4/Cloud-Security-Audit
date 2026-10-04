const { google } = require('googleapis');

/**
 * Audits GCP Cloud DNS configurations according to the checklist.
 * 
 * @param {Object} googleAuthClient - The authorized googleapis client
 * @param {string} projectId - The GCP Project ID
 */
const auditDns = async (googleAuthClient, projectId) => {
  const findings = [];
  let scannedCount = 0;

  try {
    console.log(`[Cloud DNS] Starting Cloud DNS audit for project: ${projectId}`);
    
    // Initialize googleapis resources
    const dns = google.dns({ version: 'v1', auth: googleAuthClient });

    let zonesResponse;
    try {
      zonesResponse = await dns.managedZones.list({ project: projectId });
    } catch (dnsErr) {
       console.warn("[Cloud DNS] Failed to list managed zones or API not enabled:", dnsErr.message);
       return { findings, scannedCount };
    }

    const zones = zonesResponse.data.managedZones || [];
    scannedCount += zones.length;

    for (const zone of zones) {
      const zoneName = zone.name;

      // Check 3: Ensure That DNSSEC Is Enabled for Cloud DNS
      if (!zone.dnssecConfig || zone.dnssecConfig.state !== 'on') {
        findings.push({
          id: `GCP-DNS-DNSSEC-${zoneName.substring(0, 8)}`,
          severity: 'High',
          resource: `Cloud DNS Zone (${zoneName})`,
          issue: `DNSSEC is not enabled for this managed zone.`,
          remediation: `Enable DNSSEC to protect your domains against spoofing and cache poisoning.`
        });
      } else {
        // DNSSEC is enabled, now Check 4 and 5: Ensure RSASHA1 is not used
        const keySpecs = zone.dnssecConfig.defaultKeySpecs || [];
        for (const key of keySpecs) {
          if (key.algorithm && key.algorithm.toLowerCase().includes('rsasha1')) {
            const isKsk = key.keyType === 'keySigning';
            // Check 4 (Key Signing Key) & Check 5 (Zone Signing Key)
            findings.push({
              id: `GCP-DNS-RSASHA1-${isKsk ? 'KSK' : 'ZSK'}-${zoneName.substring(0, 8)}`,
              severity: 'Critical', // Weak crypto
              resource: `Cloud DNS Zone (${zoneName})`,
              issue: `DNSSEC ${isKsk ? 'Key Signing Key (KSK)' : 'Zone Signing Key (ZSK)'} is utilizing the weak RSASHA1 algorithm.`,
              remediation: `Upgrade the DNSSEC signing algorithm to RSASHA256, RSASHA512, or ECDSA algorithms which offer much stronger cryptographic strength.`
            });
          }
        }
      }
    }

    // Check 12: Ensure Cloud DNS Logging is Enabled
    try {
      const policiesResponse = await dns.policies.list({ project: projectId });
      const policies = policiesResponse.data.policies || [];
      scannedCount += policies.length;

      if (policies.length === 0) {
        findings.push({
          id: `GCP-DNS-LOG-MISSING-${projectId.substring(0, 8)}`,
          severity: 'Low',
          resource: `Cloud DNS Policies`,
          issue: `No Cloud DNS Policies exist, meaning DNS query logging is not enabled for VPC networks.`,
          remediation: `Create a DNS Policy with 'enableLogging' set to true and attach it to your VPC networks.`
        });
      }

      for (const policy of policies) {
        if (!policy.enableLogging) {
          findings.push({
             id: `GCP-DNS-LOG-${policy.name.substring(0, 8)}`,
             severity: 'Low',
             resource: `Cloud DNS Policy (${policy.name})`,
             issue: `Cloud DNS query logging is NOT enabled.`,
             remediation: `Turn on DNS query logging for the policy to monitor name resolution activities.`
          });
        }
      }
    } catch(err) { }

    return { findings, scannedCount };

  } catch (error) {
    console.error("[Cloud DNS] Critical error during DNS audit:", error);
    return { findings: [], scannedCount: 0, error: error.message }; 
  }
};

module.exports = { auditDns };
