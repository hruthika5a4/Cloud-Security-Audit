/**
 * Audits GCP Compute Engine Virtual Machines for common security misconfigurations.
 */
const auditVMs = async (computeClient, projectClient, projectId) => {
  const findings = [];
  let scannedCount = 0;

  try {
    console.log(`[Compute Engine] Starting VM audit for project: ${projectId}`);

    // First check project-wide compute metadata settings
    try {
      const [projectResource] = await projectClient.get({ project: projectId });
      const commonInstanceMetadata = projectResource.commonInstanceMetadata?.items || [];

      const blockSshKeys = commonInstanceMetadata.find(item => item.key === 'block-project-ssh-keys');
      if (!blockSshKeys || blockSshKeys.value.toLowerCase() !== 'true') {
        findings.push({
          id: `GCP-VM-PROJ-SSH`,
          severity: 'High',
          resource: `Compute Engine (Project Level)`,
          issue: `"Block Project-Wide SSH Keys" is NOT enabled.`,
          remediation: `Enable block-project-ssh-keys at the project metadata level to prevent users from using legacy SSH keys across instances.`
        });
      }

      const enableOslogin = commonInstanceMetadata.find(item => item.key === 'enable-oslogin');
      if (!enableOslogin || enableOslogin.value.toLowerCase() !== 'true') {
        findings.push({
          id: `GCP-VM-PROJ-OSLOGIN`,
          severity: 'Medium',
          resource: `Compute Engine (Project Level)`,
          issue: `OS Login is NOT enabled for the project.`,
          remediation: `Enable OS Login to manage SSH access centrally through IAM policies rather than SSH keys.`
        });
      }
    } catch (projectErr) {
      console.warn("[Compute Engine] Failed to fetch project metadata:", projectErr.message);
    }

    // Iterate through all instances across all zones via aggregatedList
    const instancesAggregated = await computeClient.aggregatedListAsync({ project: projectId });
    for await (const [zone, instancesObject] of instancesAggregated) {
      const instances = instancesObject.instances;
      if (instances && instances.length > 0) {
        for (const instance of instances) {
          scannedCount++;
          const instanceName = instance.name;

          // Target 1: Public IP
          let hasPublicIp = false;
          if (instance.networkInterfaces) {
            for (const iface of instance.networkInterfaces) {
              if (iface.accessConfigs) {
                for (const config of iface.accessConfigs) {
                  if (config.natIP || config.type === 'ONE_TO_ONE_NAT') {
                    hasPublicIp = true;
                    break;
                  }
                }
              }
            }
          }
          if (hasPublicIp) {
            findings.push({
              id: `GCP-VM-PUBLIC-IP-${instanceName.substring(0, 8)}`,
              severity: 'High',
              resource: `Compute Instance (${instanceName})`,
              issue: `Instance possesses a Public IP address.`,
              remediation: `Remove external IP addresses and use Identity-Aware Proxy (IAP) or Cloud NAT for external communications.`
            });
          }

          // Target 2: IP Forwarding
          if (instance.canIpForward) {
            findings.push({
              id: `GCP-VM-IP-FWD-${instanceName.substring(0, 8)}`,
              severity: 'High',
              resource: `Compute Instance (${instanceName})`,
              issue: `IP Forwarding is enabled.`,
              remediation: `Disable IP Forwarding unless the instance strictly acts as a NAT gateway or router.`
            });
          }

          // Target 3: Default Service Account Usage
          // The default compute SA looks like `<project-number>-compute@developer.gserviceaccount.com`
          if (instance.serviceAccounts && instance.serviceAccounts.length > 0) {
            const saEmail = instance.serviceAccounts[0].email;
            if (saEmail.includes('-compute@developer.gserviceaccount.com')) {
              findings.push({
                id: `GCP-VM-DEF-SA-${instanceName.substring(0, 8)}`,
                severity: 'Medium',
                resource: `Compute Instance (${instanceName})`,
                issue: `Instance is configured to use the default Compute Engine service account.`,
                remediation: `Create a dedicated, least-privilege service account specifically for this workload and assign it to the instance.`
              });

              if (instance.serviceAccounts[0].scopes && instance.serviceAccounts[0].scopes.includes('https://www.googleapis.com/auth/cloud-platform')) {
                findings.push({
                  id: `GCP-VM-DEF-SA-FULL-${instanceName.substring(0, 8)}`,
                  severity: 'High',
                  resource: `Compute Instance (${instanceName})`,
                  issue: `Instance is configured to use the default Compute Engine service account with full access to all Cloud APIs.`,
                  remediation: `Limit the access scopes of the instance and explicitly assign a least-privilege service account.`
                });
              }
            }
          }

          // Target 4: Shielded VM
          if (!instance.shieldedInstanceConfig || !instance.shieldedInstanceConfig.enableSecureBoot) {
            findings.push({
              id: `GCP-VM-SHIELDED-${instanceName.substring(0, 8)}`,
              severity: 'Low', // Often Low/Medium depending on org risk tolerance
              resource: `Compute Instance (${instanceName})`,
              issue: `Secure Boot (Shielded VM) is NOT enabled.`,
              remediation: `Launch instances with Shielded VM features enabled to prevent rootkits and boot-level malware.`
            });
          }

          // Target 5: Serial Ports Connecting
          const instanceMetadata = instance.metadata?.items || [];
          const serialPortEnable = instanceMetadata.find(item => item.key === 'serial-port-enable');
          if (serialPortEnable && serialPortEnable.value.toLowerCase() === 'true') {
            findings.push({
              id: `GCP-VM-SERIAL-${instanceName.substring(0, 8)}`,
              severity: 'Medium',
              resource: `Compute Instance (${instanceName})`,
              issue: `Connecting to serial ports is enabled for this instance.`,
              remediation: `Disable 'Enable connecting to serial ports' on the VM instance unless actively troubleshooting.`
            });
          }

          // Target 6: Disks Encrypted with CMEK
          const disks = instance.disks || [];
          for (const disk of disks) {
            if (!disk.diskEncryptionKey || !disk.diskEncryptionKey.kmsKeyName) {
              findings.push({
                id: `GCP-VM-DISK-CMEK-${instanceName.substring(0, 8)}`,
                severity: 'Low',
                resource: `Compute Instance (${instanceName}) Disk (${disk.deviceName})`,
                issue: `Disk is not encrypted with a Customer-Managed Encryption Key (CMEK).`,
                remediation: `Use Customer-Managed Encryption Keys (CMEK) to encrypt disks if your compliance requirements mandate controlling the encryption keys.`
              });
            }
          }

          // Target 7: Confidential Computing
          if (!instance.confidentialInstanceConfig || !instance.confidentialInstanceConfig.enableConfidentialCompute) {
            findings.push({
              id: `GCP-VM-CONFIDENTIAL-${instanceName.substring(0, 8)}`,
              severity: 'Low',
              resource: `Compute Instance (${instanceName})`,
              issue: `Confidential Computing is NOT enabled.`,
              remediation: `Enable Confidential Computing to encrypt data in-use. Note: Requires specific machine types.`
            });
          }

          // Target 8: Deletion Protection
          if (!instance.deletionProtection) {
            findings.push({
              id: `GCP-VM-DEL-PROT-${instanceName.substring(0, 8)}`,
              severity: 'Medium',
              resource: `Compute Instance (${instanceName})`,
              issue: `Deletion protection is NOT enabled.`,
              remediation: `Enable deletion protection to prevent accidental termination of critical instances.`
            });
          }

          // Target 9: Preemptible Instances in Use
          if (instance.scheduling && instance.scheduling.preemptible) {
            findings.push({
              id: `GCP-VM-PREEMPT-${instanceName.substring(0, 8)}`,
              severity: 'Low',
              resource: `Compute Instance (${instanceName})`,
              issue: `Instance is configured as Preemptible.`,
              remediation: `Ensure preemptible instances are strictly used for fault-tolerant batch workloads, not production services requiring high availability.`
            });
          }

          // Target 10: Instance-Level Metadata Flags
          const blockKeys = instanceMetadata.find(item => item.key === 'block-project-ssh-keys');
          if (blockKeys && blockKeys.value.toLowerCase() === 'false') {
            findings.push({
              id: `GCP-VM-INST-SSH-${instanceName.substring(0, 8)}`,
              severity: 'High',
              resource: `Compute Instance (${instanceName})`,
              issue: `Instance explicitly allows project-wide SSH keys.`,
              remediation: `Remove the overriding metadata 'block-project-ssh-keys=false' to honor project-wide SSH key blocking protocols.`
            });
          }

          const osLogin = instanceMetadata.find(item => item.key === 'enable-oslogin');
          if (osLogin && osLogin.value.toLowerCase() === 'false') {
            findings.push({
              id: `GCP-VM-INST-OSLOGIN-${instanceName.substring(0, 8)}`,
              severity: 'Medium',
              resource: `Compute Instance (${instanceName})`,
              issue: `Instance explicitly disables OS Login.`,
              remediation: `Remove the overriding metadata 'enable-oslogin=false' to honor project-wide centralized identity access control.`
            });
          }
        }
      }
    }

    return {
      findings,
      scannedCount
    };

  } catch (error) {
    console.error("[Compute Engine] Error during VM audit:", error);
    // Don't completely crash the master audit if one service fails (e.g., API not enabled)
    return { findings: [], scannedCount: 0, error: error.message };
  }
};

module.exports = {
  auditVMs
};
