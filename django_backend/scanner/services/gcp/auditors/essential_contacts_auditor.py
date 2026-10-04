from googleapiclient import discovery


def audit_essential_contacts(google_auth_client, project_id):
    findings = []
    scanned_count = 1

    try:
        print(f"[Essential Contacts] Starting Essential Contacts audit for project: {project_id}")
        ec = discovery.build('essentialcontacts', 'v1', credentials=google_auth_client, cache_discovery=False)

        try:
            res = ec.projects().contacts().list(parent=f"projects/{project_id}").execute()
            contacts = res.get('contacts', [])
        except Exception as ec_err:
            print(f"[Essential Contacts] Failed to list contacts or API not enabled: {ec_err}")
            return {"findings": findings, "scannedCount": 0}

        if len(contacts) == 0:
            findings.append({
                "id": f"GCP-ESSENTIAL-CONTACTS-{project_id[:8]}",
                "severity": "High",
                "resource": f"Project ({project_id})",
                "issue": "Essential Contacts are not configured for this project. Security notifications may not reach the right people.",
                "remediation": "Configure Essential Contacts (e.g., Security, Privacy, Technical) to ensure critical notifications are routed appropriately."
            })

        return {"findings": findings, "scannedCount": scanned_count}

    except Exception as error:
        print(f"[Essential Contacts] Critical error during Essential Contacts audit: {error}")
        return {"findings": [], "scannedCount": 0, "error": str(error)}
