const { google } = require('googleapis');

/**
 * Audits GCP Dataproc Clusters for security misconfigurations.
 * 
 * @param {Object} googleAuthClient - Authorized googleapis client
 * @param {string} projectId - GCP Project ID
 */
const auditDataproc = async (googleAuthClient, projectId) => {
  const findings = [];
  let scannedCount = 0;

  try {
    console.log(`[Dataproc] Starting Dataproc cluster audit for project: ${projectId}`);
    
    // Attempting to scan Dataproc clusters across all regions using regions.clusters.list
    // Note: If you want to check specific locations, you would need to iterate locations or use the aggregated endpoint if available.
    // However, googleapis dataproc doesn't have an aggregatedList. We can default to 'global' and 'us-central1' or request the user to provide regions.
    // Alternatively, we use the compute regions list to iterate. For simplicity in this security audit context, we will query standard regions.
    
    const dataproc = google.dataproc({ version: 'v1', auth: googleAuthClient });
    const compute = google.compute({ version: 'v1', auth: googleAuthClient });

    // Fetch regions to scan
    let regions = [];
    try {
        const regionsRes = await compute.regions.list({ project: projectId });
        regions = (regionsRes.data.items || []).map(r => r.name);
    } catch(e) {
        regions = ['global', 'us-central1', 'us-east1', 'europe-west1', 'asia-southeast1'];
    }

    for (const region of regions) {
      try {
        const response = await dataproc.projects.regions.clusters.list({
          projectId: projectId,
          region: region
        });
        
        const clusters = response.data.clusters || [];
        scannedCount += clusters.length;

        for (const cluster of clusters) {
          const config = cluster.config;
          const encryptionConfig = config.encryptionConfig;
          
          if (!encryptionConfig || !encryptionConfig.gcePdKmsKeyName) {
             findings.push({
               id: `GCP-DATAPROC-CMEK-${cluster.clusterName.substring(0, 8)}`,
               severity: 'High',
               resource: `Dataproc Cluster (${cluster.clusterName}) in ${region}`,
               issue: `Dataproc cluster is NOT encrypted using a Customer-Managed Encryption Key (CMEK).`,
               remediation: `Configure the cluster with a CMEK (encryptionConfig.gcePdKmsKeyName) to encrypt the data disks attached to the cluster nodes securely.`
             });
          }
        }
      } catch (err) {
         // permissions error or API disabled - safely ignore per region
         if (err.message && err.message.includes('API has not been used')) {
            break; // Stop iterating regions if Dataproc API is disabled globally
         }
      }
    }

    return { findings, scannedCount };

  } catch (error) {
    console.error("[Dataproc] Error during Dataproc audit:", error);
    return { findings: [], scannedCount: 0, error: error.message }; 
  }
};

module.exports = { auditDataproc };
