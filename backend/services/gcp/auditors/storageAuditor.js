/**
 * Scans a GCP project's Cloud Storage Buckets for public exposure vulnerabilities.
 * 
 * @param {Object} storageClient - Instantiated @google-cloud/storage SDK client
 * @param {string} projectId - The GCP Project ID being scanned
 * @returns {Object} An object containing the findings array and count of scanned buckets
 */
const auditStorageBuckets = async (storageClient, projectId) => {
  const findings = [];
  let scannedCount = 0;

  try {
    console.log(`[Storage] Starting bucket audit for project: ${projectId}`);

    // 1. Fetch all buckets in the project
    const [buckets] = await storageClient.getBuckets();
    console.log(`[Storage] Found ${buckets.length} buckets.`);

    // 2. Iterate and analyze each bucket's IAM policy
    for (const bucket of buckets) {
      scannedCount++;
      const bucketName = bucket.name;

      try {
        const [policy] = await bucket.iam.getPolicy({ requestedPolicyVersion: 3 });
        const [metadata] = await bucket.getMetadata();

        // Target Vulnerability 1: Publicly accessible bucket
        if (policy.bindings) {
          const publicBindings = policy.bindings.filter(binding => {
            return binding.members && (
              binding.members.includes('allUsers') ||
              binding.members.includes('allAuthenticatedUsers')
            );
          });

          if (publicBindings.length > 0) {
            const exposedRoles = publicBindings.map(b => b.role).join(', ');
            findings.push({
              id: `GCP-STORAGE-PUBLIC-${bucketName.substring(0, 8)}`,
              severity: 'Critical',
              resource: `Storage Bucket (${bucketName})`,
              issue: `Bucket is publicly accessible. Exposed roles: ${exposedRoles}`,
              remediation: `Remove 'allUsers' and 'allAuthenticatedUsers' from the IAM policy.`
            });
          }
        }

        // Target Vulnerability 2: Uniform Bucket-Level Access disabled
        const ublaEnabled = metadata.iamConfiguration &&
          metadata.iamConfiguration.uniformBucketLevelAccess &&
          metadata.iamConfiguration.uniformBucketLevelAccess.enabled === true;

        if (!ublaEnabled) {
          findings.push({
            id: `GCP-STORAGE-UBLA-${bucketName.substring(0, 8)}`,
            severity: 'Medium',
            resource: `Storage Bucket (${bucketName})`,
            issue: `Uniform Bucket-Level Access (UBLA) is NOT enabled.`,
            remediation: `Enable UBLA to unify and simplify access control to prevent accidental ACL misconfigurations.`
          });
        }

        // Target Vulnerability 3: Public Access Prevention (PAP)
        const papEnforced = metadata.iamConfiguration && metadata.iamConfiguration.publicAccessPrevention === 'enforced';
        if (!papEnforced) {
          findings.push({
            id: `GCP-STORAGE-PAP-${bucketName.substring(0, 8)}`,
            severity: 'High',
            resource: `Storage Bucket (${bucketName})`,
            issue: `Public Access Prevention is NOT enforced.`,
            remediation: `Enforce Public Access Prevention to guarantee that public access to the bucket and its objects is unconditionally blocked.`
          });
        }

        // Target Vulnerability 4: Object Versioning
        const versioningEnabled = metadata.versioning && metadata.versioning.enabled === true;
        if (!versioningEnabled) {
          findings.push({
            id: `GCP-STORAGE-VERS-${bucketName.substring(0, 8)}`,
            severity: 'Low',
            resource: `Storage Bucket (${bucketName})`,
            issue: `Object Versioning is NOT enabled.`,
            remediation: `Enable object versioning to protect data against accidental deletion or modification (ransomware/malware recovery).`
          });
        }

        // Target Vulnerability 5: Data Access Logging
        const loggingEnabled = metadata.logging && metadata.logging.logBucket;
        if (!loggingEnabled) {
          findings.push({
            id: `GCP-STORAGE-LOG-${bucketName.substring(0, 8)}`,
            severity: 'Low',
            resource: `Storage Bucket (${bucketName})`,
            issue: `Cloud Storage Access Logging is NOT configured.`,
            remediation: `Configure bucket logging to maintain an audit trail of access usage.`
          });
        }

        // Target Vulnerability 6: CMEK
        const cmekConfigured = metadata.encryption && metadata.encryption.defaultKmsKeyName;
        if (!cmekConfigured) {
          findings.push({
            id: `GCP-STORAGE-CMEK-${bucketName.substring(0, 8)}`,
            severity: 'Medium',
            resource: `Storage Bucket (${bucketName})`,
            issue: `Customer-Managed Encryption Key (CMEK) is NOT configured as default.`,
            remediation: `Use CMEK instead of Google-managed keys to maintain full centralized control over decryption keys.`
          });
        }

      } catch (iamError) {
        console.warn(`[Storage] Failed to fetch IAM policy for bucket ${bucketName}. Missing storage.buckets.getIamPolicy permission?`, iamError.message);
        // We could optionally push a 'Warning' finding here about insufficient permissions to audit certain resources
      }
    }

    return {
      findings,
      scannedCount
    };

  } catch (error) {
    console.error("[Storage] Critical error during bucket audit:", error);
    throw new Error(`Cloud Storage Audit Failed: ${error.message}`);
  }
};

module.exports = {
  auditStorageBuckets
};
