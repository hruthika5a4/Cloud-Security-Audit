import datetime
from googleapiclient import discovery


def audit_api_keys(google_auth_client, project_id):
    findings = []
    scanned_count = 0

    try:
        print(f"[API Keys] Starting API Keys audit for project: {project_id}")
        apikeys = discovery.build('apikeys', 'v2', credentials=google_auth_client, cache_discovery=False)

        try:
            keys_res = apikeys.projects().locations().keys().list(
                parent=f"projects/{project_id}/locations/global"
            ).execute()
        except Exception as api_err:
            print(f"[API Keys] Failed to list API keys or API not enabled: {api_err}")
            return {"findings": findings, "scannedCount": scanned_count}

        keys = keys_res.get('keys', [])
        scanned_count = len(keys)
        now = datetime.datetime.now(datetime.timezone.utc)

        for key in keys:
            key_id = key.get('displayName') or key.get('uid') or key.get('name', '').split('/')[-1]
            short_id = key.get('uid', key_id)[:8]
            restrictions = key.get('restrictions', {})

            # Unrestricted Key
            if not restrictions:
                findings.append({
                    "id": f"GCP-APIKEY-UNRESTRICTED-{short_id}",
                    "severity": "Critical",
                    "resource": f"API Key ({key_id})",
                    "issue": "API Key has no application or API restrictions.",
                    "remediation": "Configure application restrictions (e.g., HTTP referrers, IP addresses) and restrict the key to only the APIs it needs to access."
                })
            else:
                if not restrictions.get('apiTargets'):
                    findings.append({
                        "id": f"GCP-APIKEY-NO-API-RESTRICTION-{short_id}",
                        "severity": "High",
                        "resource": f"API Key ({key_id})",
                        "issue": "API Key has application restrictions but is not restricted to specific APIs.",
                        "remediation": "Limit the API key to explicitly required APIs."
                    })

            create_time = key.get('createTime')
            if create_time:
                try:
                    dt = datetime.datetime.fromisoformat(create_time.replace('Z', '+00:00'))
                    diff_days = (now - dt).days
                    if diff_days > 90:
                        findings.append({
                            "id": f"GCP-APIKEY-ROTATION-{short_id}",
                            "severity": "Medium",
                            "resource": f"API Key ({key_id})",
                            "issue": f"API Key is {diff_days} days old. It has not been rotated in the last 90 days.",
                            "remediation": "Rotate API Keys every 90 days by creating a new key, migrating applications, and deleting the old key."
                        })
                except Exception:
                    pass

        return {"findings": findings, "scannedCount": scanned_count}

    except Exception as error:
        print(f"[API Keys] Critical error during API Keys audit: {error}")
        return {"findings": [], "scannedCount": 0, "error": str(error)}
