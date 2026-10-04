const { google } = require('googleapis');

/**
 * 🚀 GKE (Google Kubernetes Engine) Auditor
 * Checks for control plane visibility, workload identity, shielded nodes, and legacy ABAC.
 */
async function auditGKE(authClient, projectId) {
  const findings = [];
  let scannedCount = 0;

  try {
    const container = google.container({ version: 'v1', auth: authClient });

    // Fetch clusters across all locations
    const response = await container.projects.locations.clusters.list({
      parent: `projects/${projectId}/locations/-`,
    });

    const clusters = response.data.clusters || [];
    scannedCount = clusters.length;

    for (const cluster of clusters) {
      const clusterId = cluster.name;
      const location = cluster.location;

      // 1. Control Plane Exposure
      const isPublic = !cluster.privateClusterConfig?.enablePrivateNodes;
      const hasAuthNetworks = cluster.masterAuthorizedNetworksConfig?.enabled || false;

      if (isPublic && !hasAuthNetworks) {
        findings.push({
          id: 'GCP-GKE-PUBLIC-ENDPOINT',
          severity: 'Critical',
          resource: `GKE Cluster (${clusterId})`,
          issue: 'GKE control plane has a public endpoint with no authorized networks configured. Anyone can attempt to reach the API server.',
          remediation: 'Enable Private Nodes and configure Master Authorized Networks to restrict access to the control plane.'
        });
      } else if (isPublic) {
        findings.push({
          id: 'GCP-GKE-PUBLIC-ENDPOINT-RESTRICTED',
          severity: 'Medium',
          resource: `GKE Cluster (${clusterId})`,
          issue: 'GKE control plane endpoint is public, although protected by authorized networks.',
          remediation: 'Consider using a private endpoint to completely isolate the control plane from the internet.'
        });
      }

      // 2. Legacy ABAC
      if (cluster.legacyAbac?.enabled) {
        findings.push({
          id: 'GCP-GKE-LEGACY-ABAC',
          severity: 'High',
          resource: `GKE Cluster (${clusterId})`,
          issue: 'Legacy ABAC / Attribute-Based Access Control is enabled. This bypasses RBAC and can lead to excessive privileges.',
          remediation: 'Disable Legacy ABAC and use Kubernetes RBAC for more granular security.'
        });
      }

      // 3. Workload Identity
      if (!cluster.workloadIdentityConfig?.workloadPool) {
        findings.push({
          id: 'GCP-GKE-WORKLOAD-IDENTITY-DISABLED',
          severity: 'High',
          resource: `GKE Cluster (${clusterId})`,
          issue: 'Workload Identity is not enabled. Pods may be using Compute Engine default service accounts with too much power.',
          remediation: 'Enable Workload Identity to securely map Kubernetes service accounts to GCP service accounts.'
        });
      }

      // 4. Shielded Nodes
      if (!cluster.shieldedNodes?.enabled) {
        findings.push({
          id: 'GCP-GKE-SHIELDED-NODES-DISABLED',
          severity: 'Medium',
          resource: `GKE Cluster (${clusterId})`,
          issue: 'Shielded GKE Nodes are disabled. This leaves nodes vulnerable to boot-level rootkits or persistence.',
          remediation: 'Enable Shielded GKE Nodes to provide strong, verifiable node identity and integrity.'
        });
      }

      // 5. Binary Authorization
      if (!cluster.binaryAuthorization?.enabled) {
        findings.push({
          id: 'GCP-GKE-BINARY-AUTH-DISABLED',
          severity: 'Low',
          resource: `GKE Cluster (${clusterId})`,
          issue: 'Binary Authorization is disabled. Untrusted images could be deployed to the cluster.',
          remediation: 'Enable Binary Authorization to ensure only signed, trustworthy images are deployed.'
        });
      }
    }
  } catch (err) {
    if (err.code === 403 || err.code === 404) {
      // API not enabled or permission denied is common
    } else {
      console.error('[GKE Auditor] Error:', err.message);
    }
  }

  return { findings, scannedCount };
}

module.exports = { auditGKE };
