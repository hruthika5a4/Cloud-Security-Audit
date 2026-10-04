const { google } = require('googleapis');

/**
 * ⚡ Serverless Auditor (Cloud Run & Cloud Functions)
 * Checks for unauthenticated access, public ingress settings, and risky service accounts.
 */
async function auditServerless(authClient, projectId) {
  const findings = [];
  let scannedCount = 0;

  try {
    const cloudRun = google.run({ version: 'v1', auth: authClient });
    const cloudFunctions = google.cloudfunctions({ version: 'v1', auth: authClient });

    // 1. Audit Cloud Run Services
    try {
      const runRes = await cloudRun.projects.locations.services.list({
        parent: `projects/${projectId}/locations/-`,
      });

      const services = runRes.data.items || [];
      scannedCount += services.length;

      for (const svc of services) {
        const name = svc.metadata.name;
        const region = svc.metadata.labels?.['cloud.googleapis.com/location'] || 'unknown';
        const ingress = svc.metadata.annotations?.['run.googleapis.com/ingress'] || 'all';

        // Check if IAM allows allUsers (Public Access)
        let isPublic = false;
        try {
          const policy = await cloudRun.projects.locations.services.getIamPolicy({
            resource: `projects/${projectId}/locations/${region}/services/${name}`,
          });
          const bindings = policy.data.bindings || [];
          isPublic = bindings.some(b => 
            (b.role === 'roles/run.invoker' || b.role === 'roles/viewer') && 
            b.members?.some(m => m === 'allUsers' || m === 'allAuthenticatedUsers')
          );
        } catch (e) {
          // ignore permission errors for individual policy gets
        }

        if (isPublic) {
          findings.push({
            id: 'GCP-CLOUDRUN-PUBLIC-ACCESS',
            severity: 'High',
            resource: `Cloud Run Service (${name})`,
            issue: 'Service is accessible to unauthenticated users or all authenticated users.',
            remediation: 'Remove "allUsers" or "allAuthenticatedUsers" from the IAM invoker role for this service.'
          });
        }

        if (ingress === 'all') {
          findings.push({
            id: 'GCP-CLOUDRUN-ALLOW-ALL-INGRESS',
            severity: 'Medium',
            resource: `Cloud Run Service (${name})`,
            issue: 'Ingress settings are set to "Allow All", meaning it can be reached directly via its default URL.',
            remediation: 'Change ingress to "Internal" or "Internal and Cloud Load Balancing" if appropriate for your architecture.'
          });
        }
      }
    } catch (err) {
      // Cloud Run APIอาจไม่เปิด
    }

    // 2. Audit Cloud Functions
    try {
      const fnRes = await cloudFunctions.projects.locations.functions.list({
        parent: `projects/${projectId}/locations/-`,
      });

      const functions = fnRes.data.functions || [];
      scannedCount += functions.length;

      for (const fn of functions) {
        const name = fn.name.split('/').pop();
        const ingress = fn.ingressSettings || 'ALLOW_ALL';

        if (ingress === 'ALLOW_ALL') {
          findings.push({
            id: 'GCP-FUNCTION-ALLOW-ALL-INGRESS',
            severity: 'Medium',
            resource: `Cloud Function (${name})`,
            issue: 'Ingress settings are set to "Allow All".',
            remediation: 'Restrict ingress to "internal-only" or use an API Gateway/Load Balancer.'
          });
        }

        // Service Account Check
        if (fn.serviceAccountEmail?.includes('compute@developer.gserviceaccount.com')) {
          findings.push({
            id: 'GCP-FUNCTION-DEFAULT-SA',
            severity: 'Medium',
            resource: `Cloud Function (${name})`,
            issue: 'Function is using the default Compute Engine service account, which often has broad "Editor" permissions.',
            remediation: 'Create a dedicated service account with minimal required permissions for this function.'
          });
        }
      }
    } catch (err) {
      // API not enabled
    }

  } catch (err) {
    console.error('[Serverless Auditor] Global Error:', err.message);
  }

  return { findings, scannedCount };
}

module.exports = { auditServerless };
