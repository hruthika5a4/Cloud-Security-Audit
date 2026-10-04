from googleapiclient import discovery


def audit_logging(google_auth_client, project_id):
    findings = []
    scanned_count = 1

    try:
        print(f"[Logging] Starting Logging & Observability audit for project: {project_id}")
        logging = discovery.build('logging', 'v2', credentials=google_auth_client, cache_discovery=False)
        crm = discovery.build('cloudresourcemanager', 'v1', credentials=google_auth_client, cache_discovery=False)
        storage = discovery.build('storage', 'v1', credentials=google_auth_client, cache_discovery=False)
        serviceusage = discovery.build('serviceusage', 'v1', credentials=google_auth_client, cache_discovery=False)
        accessapproval = discovery.build('accessapproval', 'v1', credentials=google_auth_client, cache_discovery=False)

        # 1. Audit Configs
        try:
            iam_res = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
            audit_configs = iam_res.get('auditConfigs', [])
            all_services_audited = False

            for cfg in audit_configs:
                if cfg.get('service') == 'allServices':
                    log_types = [c.get('logType') for c in cfg.get('auditLogConfigs', [])]
                    if 'ADMIN_READ' in log_types and 'DATA_READ' in log_types and 'DATA_WRITE' in log_types:
                        all_services_audited = True

            if not all_services_audited:
                findings.append({
                    "id": f"GCP-LOG-AUDIT-{project_id[:8]}",
                    "severity": "High",
                    "resource": "Project IAM Audit Settings",
                    "issue": "Cloud Audit Logging is not properly configured to capture all log types (ADMIN_READ, DATA_READ, DATA_WRITE) for 'allServices'.",
                    "remediation": "Configure Cloud Audit Logs to track all administrative and data access events across all services."
                })
        except Exception:
            pass

        # 2. Sinks & Retention
        try:
            sinks_res = logging.projects().sinks().list(parent=f"projects/{project_id}").execute()
            sinks = sinks_res.get('sinks', [])
            scanned_count += len(sinks)

            catch_all_exists = False
            for sink in sinks:
                sink_filter = sink.get('filter', '').strip()
                if not sink_filter:
                    catch_all_exists = True

                dest = sink.get('destination', '')
                if dest.startswith('storage.googleapis.com/'):
                    bucket_name = dest.replace('storage.googleapis.com/', '')
                    try:
                        b_res = storage.buckets().get(bucket=bucket_name).execute()
                        retention = b_res.get('retentionPolicy', {})
                        if not retention.get('isLocked'):
                            findings.append({
                                "id": f"GCP-LOG-BUCKET-LOCK-{bucket_name[:8]}",
                                "severity": "Medium",
                                "resource": f"Cloud Storage Sink ({bucket_name})",
                                "issue": "Retention policies on the bucket used for exporting logs are not configured with a Bucket Lock.",
                                "remediation": "Configure a retention policy and lock it to prevent log entries from being deleted or modified."
                            })
                    except Exception:
                        pass

            if len(sinks) == 0 or not catch_all_exists:
                findings.append({
                    "id": f"GCP-LOG-SINK-{project_id[:8]}",
                    "severity": "Medium",
                    "resource": "Project Sinks",
                    "issue": "Proper 'catch-all' Logging Sinks are not configured to export all log entries.",
                    "remediation": "Configure a log sink without exclusionary filters, exporting to an aggregation destination like BigQuery or Cloud Storage."
                })
        except Exception:
            pass

        # 3. Metrics
        try:
            metrics_res = logging.projects().metrics().list(parent=f"projects/{project_id}").execute()
            metrics = metrics_res.get('metrics', [])
            scanned_count += len(metrics)

            all_filters = " || ".join([m.get('filter', '').lower() for m in metrics])

            required_metrics = [
                {'id': 'OWNERSHIP', 'keywords': ['resourcemanager.projects.setiampolicy', 'roles/owner'], 'title': 'Project Ownership Assignments/Changes'},
                {'id': 'AUDIT_CFG', 'keywords': ['auditconfig'], 'title': 'Audit Configuration Changes'},
                {'id': 'CUSTOM_ROLE', 'keywords': ['iam.roles.create', 'iam.roles.delete', 'iam.roles.update'], 'title': 'Custom Role Changes'},
                {'id': 'FW_RULE', 'keywords': ['compute.firewalls.insert', 'compute.firewalls.patch', 'compute.firewalls.delete'], 'title': 'VPC Network Firewall Rule Changes'},
                {'id': 'VPC_ROUTE', 'keywords': ['compute.routes.insert', 'compute.routes.delete'], 'title': 'VPC Network Route Changes'},
                {'id': 'VPC_NET', 'keywords': ['compute.networks.insert', 'compute.networks.delete'], 'title': 'VPC Network Changes'},
                {'id': 'STORAGE_IAM', 'keywords': ['storage.setiampermissions'], 'title': 'Cloud Storage IAM Permission Changes'},
                {'id': 'SQL_CFG', 'keywords': ['cloudsql.instances.update'], 'title': 'SQL Instance Configuration Changes'}
            ]

            for req in required_metrics:
                has_metric = any(kw in all_filters for kw in req['keywords'])
                if not has_metric:
                    findings.append({
                        "id": f"GCP-LOG-METRIC-{req['id']}-{project_id[:8]}",
                        "severity": "Low",
                        "resource": "Log Metrics",
                        "issue": f"Log Metric Filter and Alerts do not exist for {req['title']}.",
                        "remediation": "Create a log metric matching the pertinent event logs, and configure a Cloud Monitoring Alert Policy to notify administrators on occurrence."
                    })
        except Exception:
            pass

        # 4. Asset Inventory
        try:
            su_res = serviceusage.services().get(name=f"projects/{project_id}/services/cloudasset.googleapis.com").execute()
            if su_res.get('state') != 'ENABLED':
                findings.append({
                    "id": f"GCP-OBS-ASSET-{project_id[:8]}",
                    "severity": "Low",
                    "resource": "Cloud Asset Inventory API",
                    "issue": "Cloud Asset Inventory is not enabled.",
                    "remediation": "Enable the Cloud Asset API to allow historical tracking and monitoring of GCP resource configurations."
                })
        except Exception:
            pass

        # 5. Access Transparency & Approval
        try:
            su_trans = serviceusage.services().get(name=f"projects/{project_id}/services/accesstransparency.googleapis.com").execute()
            if su_trans.get('state') != 'ENABLED':
                findings.append({
                    "id": f"GCP-OBS-TRANSPARENCY-{project_id[:8]}",
                    "severity": "Medium",
                    "resource": "Access Transparency API",
                    "issue": "Access Transparency is not enabled.",
                    "remediation": "If using GCP Organizations, enable Access Transparency to ensure Google personnel actions on your data are logged."
                })

            appr_res = accessapproval.projects().getAccessApprovalSettings(name=f"projects/{project_id}/accessApprovalSettings").execute()
            if not appr_res.get('enrolledServices'):
                findings.append({
                    "id": f"GCP-OBS-APPROVAL-{project_id[:8]}",
                    "severity": "Medium",
                    "resource": "Access Approval Settings",
                    "issue": "Access Approval is not enabled or lacks enrolled services.",
                    "remediation": "Enable Access Approval to require explicit approval before Google support can access your data."
                })
        except Exception:
            if not any("GCP-OBS-TRANSPARENCY" in f.get('id', '') for f in findings):
                findings.append({
                    "id": f"GCP-OBS-TRANSPARENCY-{project_id[:8]}",
                    "severity": "Medium",
                    "resource": "Access Transparency",
                    "issue": "Access Transparency is likely not enabled (requires Organization context).",
                    "remediation": "Enable Access Transparency at the organization or project level."
                })

        return {"findings": findings, "scannedCount": scanned_count}

    except Exception as error:
        print(f"[Logging] Critical error during Logging audit: {error}")
        return {"findings": [], "scannedCount": 0, "error": str(error)}
