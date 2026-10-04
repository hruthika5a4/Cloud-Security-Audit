const { google } = require('googleapis');

/**
 * 🛰️ Networking Depth Auditor
 * Checks for VPC Flow Logs, RDP/SSH exposure, and more.
 */
async function auditNetworkingDepth(authClient, projectId) {
  const findings = [];
  let scannedCount = 0;

  try {
    const compute = google.compute({ version: 'v1', auth: authClient });

    // 1. VPC Flow Logs Audit
    const subnetRes = await compute.subnetworks.aggregatedList({
      project: projectId,
    });

    const items = subnetRes.data.items || {};
    for (const [, scopedList] of Object.entries(items)) {
      const subnets = scopedList.subnetworks || [];
      for (const subnet of subnets) {
        scannedCount++;
        // Skip default networks or subnets that don't belong to the project
        if (subnet.network.endsWith('/default')) continue;

        if (!subnet.enableFlowLogs) {
          findings.push({
            id: 'GCP-NET-FLOW-LOGS-DISABLED',
            severity: 'Low',
            resource: `Subnet (${subnet.name})`,
            issue: 'VPC Flow Logs are disabled for this subnetwork.',
            remediation: 'Enable VPC Flow Logs to improve network visibility, auditing, and troubleshooting capacity.'
          });
        }
      }
    }

    // 2. RDP/SSH Exposure Check (Advanced check from reference)
    const fwRes = await compute.firewalls.list({ project: projectId });
    const firewalls = fwRes.data.items || [];
    scannedCount += firewalls.length;

    for (const fw of firewalls) {
      if (fw.direction === 'INGRESS' && !fw.disabled && fw.allowed) {
        const isPublic = fw.sourceRanges?.some(range => range === '0.0.0.0/0');
        if (isPublic) {
          const hasRdp = fw.allowed.some(a => a.IPProtocol === 'all' || (a.ports && a.ports.some(p => p === '3389' || p.includes('3389'))));
          const hasSsh = fw.allowed.some(a => a.IPProtocol === 'all' || (a.ports && a.ports.some(p => p === '22' || p.includes('22'))));

          if (hasRdp) {
            findings.push({
              id: 'GCP-NET-PUBLIC-RDP',
              severity: 'Critical',
              resource: `Firewall Rule (${fw.name})`,
              issue: 'Firewall allows RDP (port 3389) access from ANY IP address.',
              remediation: 'Restrict RDP access to specific trusted source IP ranges or use IAP (Identity-Aware Proxy).'
            });
          }
          if (hasSsh) {
            findings.push({
              id: 'GCP-NET-PUBLIC-SSH',
              severity: 'High',
              resource: `Firewall Rule (${fw.name})`,
              issue: 'Firewall allows SSH (port 22) access from ANY IP address.',
              remediation: 'Restrict SSH access to specific trusted source IP ranges or use IAP.'
            });
          }
        }
      }
    }

  } catch (err) {
    if (err.code !== 403 && err.code !== 404) {
      console.error('[Networking Depth Auditor] Error:', err.message);
    }
  }

  return { findings, scannedCount };
}

module.exports = { auditNetworkingDepth };
