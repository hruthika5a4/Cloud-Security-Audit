const { google } = require('googleapis');

/**
 * Audits GCP IAM & Admin configurations according to the checklist.
 * 
 * @param {Object} googleAuthClient - The authorized googleapis client
 * @param {string} projectId - The GCP Project ID
 */
const auditIAM = async (googleAuthClient, projectId) => {
  const findings = [];
  let scannedCount = 0;

  try {
    console.log(`[IAM] Starting IAM audit for project: ${projectId}`);
    
    // Initialize googleapis resources
    const iam = google.iam({ version: 'v1', auth: googleAuthClient });
    const cloudresourcemanager = google.cloudresourcemanager({ version: 'v1', auth: googleAuthClient });

    // 1. Audit Project-Level IAM Policy (Check for Admin privileges, SA Token Creator, and SOD)
    try {
      const response = await cloudresourcemanager.projects.getIamPolicy({
        resource: projectId,
        requestBody: {}
      });
      const policy = response.data;
      
      const memberRoles = {};

      if (policy && policy.bindings) {
        policy.bindings.forEach(binding => {
          // Track roles per member for SOD
          binding.members.forEach(member => {
            if (!memberRoles[member]) memberRoles[member] = new Set();
            memberRoles[member].add(binding.role);
          });

          // Check if Service Accounts have admin/owner privileges
          if (binding.role === 'roles/owner' || binding.role === 'roles/editor') {
            const serviceAccounts = binding.members.filter(m => m.startsWith('serviceAccount:'));
            serviceAccounts.forEach(sa => {
              findings.push({
                id: `GCP-IAM-SA-ADMIN-${sa.substring(15, 23)}`,
                severity: 'High',
                resource: `IAM Policy (Project: ${projectId})`,
                issue: `Service Account ${sa.replace('serviceAccount:', '')} has primitive admin privileges (${binding.role}).`,
                remediation: `Apply the Principle of Least Privilege by removing primitive roles and replacing them with specific predefined roles.`
              });
            });

            // Added: Warn if human users hold unrestricted owner powers
            if (binding.role === 'roles/owner') {
               const users = binding.members.filter(m => m.startsWith('user:'));
               users.forEach(user => {
                 findings.push({
                   id: `GCP-IAM-USER-OWNER-${user.substring(5, 13)}`,
                   severity: 'Medium',
                   resource: `IAM Policy (Project: ${projectId})`,
                   issue: `User ${user.replace('user:', '')} possesses the sweeping primitive 'roles/owner' role.`,
                   remediation: `Assign specific predefined responsibilities rather than permanent primitive ownership.`
                 });
               });
            }
          }

          // Check for Service Account User / Token Creator at project level
          if (binding.role === 'roles/iam.serviceAccountUser' || binding.role === 'roles/iam.serviceAccountTokenCreator') {
            const users = binding.members.filter(m => m.startsWith('user:'));
            users.forEach(user => {
              findings.push({
                id: `GCP-IAM-PROJECT-TOKEN-${user.substring(5, 13)}`,
                severity: 'Medium',
                resource: `IAM Policy (Project: ${projectId})`,
                issue: `User ${user.replace('user:', '')} has ${binding.role} at the Project Level.`,
                remediation: `Remove the role from the project level. Assign it specifically to the individual Service Account the user needs access to.`
              });
            });
          }
        });

        // Enforcement of advanced Separation of Duties
        for (const [member, roles] of Object.entries(memberRoles)) {
          // SoD: KMS roles
          if (roles.has('roles/cloudkms.admin') && (roles.has('roles/cloudkms.cryptoKeyEncrypterDecrypter') || roles.has('roles/owner') || roles.has('roles/editor'))) {
             findings.push({
               id: `GCP-IAM-KMS-SOD-${member.replace(/[^a-zA-Z0-9]/g, '').substring(0, 8)}`,
               severity: 'High',
               resource: `IAM Policy (Project: ${projectId})`,
               issue: `Identity ${member.replace(/^[a-zA-Z]+:/, '')} has both KMS Admin and Encrypter/Decrypter (or primitive Admin) roles, violating Separation of Duties.`,
               remediation: `Remove either the administrative or data access role from this identity. Use distinct accounts for KMS administration and usage.`
             });
          }

          // SoD: Network vs Compute Compute Admin
          if (roles.has('roles/compute.networkAdmin') && roles.has('roles/iam.serviceAccountUser')) {
             findings.push({
               id: `GCP-IAM-NET-SOD-${member.replace(/[^a-zA-Z0-9]/g, '').substring(0, 8)}`,
               severity: 'Medium',
               resource: `IAM Policy (Project: ${projectId})`,
               issue: `Identity ${member.replace(/^[a-zA-Z]+:/, '')} holds both Network Admin and Service Account User capabilities.`,
               remediation: `Isolate network definitions from compute deployment identities to restrict potential lateral escalation routes.`
             });
          }
        }
      }
    } catch (iamPolErr) {
       console.warn("[IAM] Failed to fetch project IAM Policy:", iamPolErr.message);
    }

    // 2. Audit Service Account Keys
    try {
      const saResponse = await iam.projects.serviceAccounts.list({
        name: `projects/${projectId}`
      });
      
      const serviceAccounts = saResponse.data.accounts || [];
      scannedCount += serviceAccounts.length;

      for (const sa of serviceAccounts) {
        const keyResponse = await iam.projects.serviceAccounts.keys.list({
          name: sa.name,
          keyTypes: ['USER_MANAGED'] // Only fetch user-managed keys
        });

        const userManagedKeys = keyResponse.data.keys || [];
        for (const key of userManagedKeys) {
          // General warning for user managed keys (not strictly a failure, but noted as info/medium depending on context, keeping medium here)
           findings.push({
            id: `GCP-IAM-USER-KEY-${sa.email.substring(0, 8)}`,
            severity: 'Low',
            resource: `Service Account (${sa.email})`,
            issue: `Service Account has a User-Managed Key (id: ${key.name.split('/').pop()}). GCP-managed keys are preferred.`,
            remediation: `Prefer relying on GCP-managed short-lived credentials.`
          });

          // Check 3: Ensure User-Managed/External Keys for Service Accounts Are Rotated Every 90 Days
          if (key.validAfterTime) {
            const validAfterTime = new Date(key.validAfterTime);
            const now = new Date();
            const diffDays = Math.floor((now - validAfterTime) / (1000 * 60 * 60 * 24));
            
            if (diffDays > 90) {
              findings.push({
                id: `GCP-IAM-KEY-ROTATION-${sa.email.substring(0, 8)}`,
                severity: 'High',
                resource: `SA Key (${sa.email})`,
                issue: `User-managed key is ${diffDays} days old. It has not been rotated in the last 90 days.`,
                remediation: `Rotate user-managed keys every 90 days.`
              });
            }
          }
        }
      }
    } catch (saErr) {
      console.warn("[IAM] Failed to list Service Accounts:", saErr.message);
    }

    return { findings, scannedCount };

  } catch (error) {
    console.error("[IAM] Critical error during IAM audit:", error);
    return { findings: [], scannedCount: 0, error: error.message }; 
  }
};

module.exports = { auditIAM };
