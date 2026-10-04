const { google } = require('googleapis');

/**
 * Audits GCP Essential Contacts configurations according to the checklist.
 * 
 * @param {Object} googleAuthClient - The authorized googleapis client
 * @param {string} projectId - The GCP Project ID
 */
const auditEssentialContacts = async (googleAuthClient, projectId) => {
  const findings = [];
  let scannedCount = 1; // Scanning the project itself for contacts

  try {
    console.log(`[Essential Contacts] Starting Essential Contacts audit for project: ${projectId}`);
    
    // Initialize googleapis resources
    const essentialcontacts = google.essentialcontacts({ version: 'v1', auth: googleAuthClient });

    let contactsResponse;
    try {
      contactsResponse = await essentialcontacts.projects.contacts.list({
        parent: `projects/${projectId}`
      });
    } catch (ecErr) {
       console.warn("[Essential Contacts] Failed to list contacts or API not enabled:", ecErr.message);
       // Distinguish between API not enabled vs no contacts
       if (ecErr.message.includes("API has not been used") || ecErr.message.includes("Permission denied")) {
           // We'll treat API not enabled / Permission denied as a finding depending on strictness
           // But normally, if they can't even check, let's just log and return.
           return { findings, scannedCount: 0 };
       }
       return { findings, scannedCount: 0 };
    }

    const contacts = contactsResponse.data.contacts || [];

    if (contacts.length === 0) {
      findings.push({
        id: `GCP-ESSENTIAL-CONTACTS-${projectId.substring(0, 8)}`,
        severity: 'High',
        resource: `Project (${projectId})`,
        issue: `Essential Contacts are not configured for this project. Security notifications may not reach the right people.`,
        remediation: `Configure Essential Contacts (e.g., Security, Privacy, Technical) to ensure critical notifications are routed appropriately.`
      });
    }

    return { findings, scannedCount };

  } catch (error) {
    console.error("[Essential Contacts] Critical error during Essential Contacts audit:", error);
    return { findings: [], scannedCount: 0, error: error.message }; 
  }
};

module.exports = { auditEssentialContacts };
