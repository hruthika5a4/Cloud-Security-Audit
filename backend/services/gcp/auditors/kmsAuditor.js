const { google } = require('googleapis');

/**
 * Audits GCP Cloud KMS configurations according to the checklist.
 * 
 * @param {Object} googleAuthClient - The authorized googleapis client
 * @param {string} projectId - The GCP Project ID
 */
const auditKMS = async (googleAuthClient, projectId) => {
  const findings = [];
  let scannedCount = 0;

  try {
    console.log(`[KMS] Starting KMS audit for project: ${projectId}`);

    // Initialize googleapis resources
    const cloudkms = google.cloudkms({ version: 'v1', auth: googleAuthClient });

    // Let's get all locations
    let locationsResponse;
    try {
      locationsResponse = await cloudkms.projects.locations.list({
        name: `projects/${projectId}`
      });
    } catch (locErr) {
      console.warn("[KMS] Failed to list locations or API not enabled:", locErr.message);
      return { findings, scannedCount, skipped: true, reason: locErr.message || "API not enabled" };
    }

    const locations = locationsResponse.data.locations || [];

    for (const location of locations) {
      // Get all key rings in the location
      const keyRingsResponse = await cloudkms.projects.locations.keyRings.list({
        parent: location.name
      }).catch(err => ({ data: { keyRings: [] } })); // catch if no permission

      const keyRings = keyRingsResponse.data.keyRings || [];
      scannedCount += keyRings.length;

      for (const keyRing of keyRings) {

        // Check KeyRing IAM
        try {
          const iamPolicy = await cloudkms.projects.locations.keyRings.getIamPolicy({
            resource: keyRing.name
          });
          const bindings = iamPolicy.data.bindings || [];
          for (const binding of bindings) {
            if (binding.members.includes('allUsers') || binding.members.includes('allAuthenticatedUsers')) {
              findings.push({
                id: `GCP-KMS-PUBLIC-KEYRING-${keyRing.name.split('/').pop().substring(0, 8)}`,
                severity: 'Critical',
                resource: `KMS KeyRing (${keyRing.name.split('/').pop()})`,
                issue: `KeyRing is publicly accessible via '${binding.members.find(m => m.startsWith('all'))}'.`,
                remediation: `Remove 'allUsers' or 'allAuthenticatedUsers' from the KeyRing's IAM policy.`
              });
            }
          }
        } catch (e) {
          // ignore IAM fetch errors
        }

        // Get keys inside key ring
        const keysResponse = await cloudkms.projects.locations.keyRings.cryptoKeys.list({
          parent: keyRing.name
        }).catch(err => ({ data: { cryptoKeys: [] } }));

        const cryptoKeys = keysResponse.data.cryptoKeys || [];
        scannedCount += cryptoKeys.length;

        for (const key of cryptoKeys) {

          // Check CryptoKey IAM
          try {
            const keyIamPolicy = await cloudkms.projects.locations.keyRings.cryptoKeys.getIamPolicy({
              resource: key.name
            });
            const keyBindings = keyIamPolicy.data.bindings || [];
            for (const binding of keyBindings) {
              if (binding.members.includes('allUsers') || binding.members.includes('allAuthenticatedUsers')) {
                findings.push({
                  id: `GCP-KMS-PUBLIC-KEY-${key.name.split('/').pop().substring(0, 8)}`,
                  severity: 'Critical',
                  resource: `KMS CryptoKey (${key.name.split('/').pop()})`,
                  issue: `CryptoKey is publicly accessible via '${binding.members.find(m => m.startsWith('all'))}'.`,
                  remediation: `Remove 'allUsers' or 'allAuthenticatedUsers' from the CryptoKey's IAM policy.`
                });
              }
            }
          } catch (e) { }

          // Check Rotation Period
          if (key.purpose === 'ENCRYPT_DECRYPT') {
            let rotationDays = -1;
            if (key.rotationPeriod) {
              // rotationPeriod is like "7776000s"
              const seconds = parseInt(key.rotationPeriod.replace('s', ''), 10);
              rotationDays = Math.floor(seconds / (24 * 60 * 60));
            }

            if (rotationDays === -1) {
              findings.push({
                id: `GCP-KMS-ROTATION-${key.name.split('/').pop().substring(0, 8)}`,
                severity: 'High',
                resource: `KMS CryptoKey (${key.name.split('/').pop()})`,
                issue: `Customer Managed Key (CMK) does not have a rotation schedule configured.`,
                remediation: `Configure automatic rotation for this key, ensuring it rotates at least annually (every 365 days).`
              });
            } else if (rotationDays > 365) {
              findings.push({
                id: `GCP-KMS-ROTATION-${key.name.split('/').pop().substring(0, 8)}`,
                severity: 'Medium',
                resource: `KMS CryptoKey (${key.name.split('/').pop()})`,
                issue: `Key rotation period is ${rotationDays} days, which exceeds the recommended annual (365 days) rotation.`,
                remediation: `Reduce the rotation period to 365 days or fewer.`
              });
            }
          }
        }
      }
    }

    return { findings, scannedCount };

  } catch (error) {
    console.error("[KMS] Critical error during KMS audit:", error);
    return { findings: [], scannedCount: 0, error: error.message };
  }
};

module.exports = { auditKMS };
