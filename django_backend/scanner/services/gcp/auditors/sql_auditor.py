from googleapiclient import discovery


def audit_cloud_sql(google_auth_client, project_id):
    findings = []
    scanned_count = 0

    try:
        print(f"[Cloud SQL] Starting SQL audit for project: {project_id}")
        sqladmin = discovery.build('sqladmin', 'v1beta4', credentials=google_auth_client, cache_discovery=False)

        res = sqladmin.instances().list(project=project_id).execute()
        instances = res.get('items', [])
        scanned_count = len(instances)

        for inst in instances:
            inst_name = inst.get('name', 'unknown')
            config = inst.get('settings', {})
            if not config:
                continue

            ip_config = config.get('ipConfiguration', {})

            # 1. Require SSL
            if not ip_config.get('requireSsl'):
                findings.append({
                    "id": f"GCP-SQL-SSL-{inst_name[:8]}",
                    "severity": "Critical",
                    "resource": f"Cloud SQL Database ({inst_name})",
                    "issue": "Incoming connections are NOT required to use SSL.",
                    "remediation": "Modify the instance network settings to explicitly require SSL for all incoming connections."
                })

            # 2. Public IP & 0.0.0.0/0 Authorized Networks
            ip_addresses = inst.get('ipAddresses', [])
            has_public_ip = any(ip.get('type') == 'PRIMARY' for ip in ip_addresses)
            if has_public_ip:
                findings.append({
                    "id": f"GCP-SQL-PUBLIC-{inst_name[:8]}",
                    "severity": "High",
                    "resource": f"Cloud SQL Database ({inst_name})",
                    "issue": "Database Instance possesses a Public IP address.",
                    "remediation": "Configure the instance to use Private IP only for internal VPC communication if public access isn't strictly necessary."
                })

            auth_networks = ip_config.get('authorizedNetworks', [])
            allows_all = any(net.get('value') in ['0.0.0.0/0', '::/0'] for net in auth_networks)
            if allows_all:
                findings.append({
                    "id": f"GCP-SQL-OPEN-{inst_name[:8]}",
                    "severity": "Critical",
                    "resource": f"Cloud SQL Database ({inst_name})",
                    "issue": "Authorized networks explicitly whitelist all public IPs (0.0.0.0/0).",
                    "remediation": "Remove 0.0.0.0/0 from Authorized Networks. Restrict access to specific, known IP ranges or utilize Cloud SQL Proxy."
                })

            # 3. Backups & PITR
            backup_config = config.get('backupConfiguration', {})
            if not backup_config.get('enabled'):
                findings.append({
                    "id": f"GCP-SQL-BACKUP-{inst_name[:8]}",
                    "severity": "High",
                    "resource": f"Cloud SQL Database ({inst_name})",
                    "issue": "Automated Backups are NOT configured.",
                    "remediation": "Enable automated daily backups to protect against data loss."
                })
            elif not backup_config.get('pointInTimeRecoveryEnabled'):
                findings.append({
                    "id": f"GCP-SQL-PITR-{inst_name[:8]}",
                    "severity": "Medium",
                    "resource": f"Cloud SQL Database ({inst_name})",
                    "issue": "Point-in-Time Recovery (PITR) is NOT enabled.",
                    "remediation": "Enable point-in-time recovery to allow restoring your database natively from a specific operational state."
                })

            # 4. Database Flags
            db_version = inst.get('databaseVersion', '')
            flags = config.get('databaseFlags', [])
            flag_map = {f.get('name'): f.get('value') for f in flags}

            if 'POSTGRES' in db_version:
                required_flags = [
                    {'name': 'log_checkpoints', 'expected': 'on', 'severity': 'Medium'},
                    {'name': 'log_connections', 'expected': 'on', 'severity': 'Medium'},
                    {'name': 'log_disconnections', 'expected': 'on', 'severity': 'Medium'},
                    {'name': 'log_lock_waits', 'expected': 'on', 'severity': 'Medium'},
                    {'name': 'log_min_messages', 'expected': 'warning', 'altExpected': 'error', 'severity': 'Medium'},
                    {'name': 'log_temp_files', 'expected': '0', 'severity': 'Low'},
                    {'name': 'log_min_duration_statement', 'expected': '-1', 'severity': 'Low'}
                ]
                for rf in required_flags:
                    val = flag_map.get(rf['name'])
                    if val != rf['expected'] and val != rf.get('altExpected'):
                        findings.append({
                            "id": f"GCP-SQL-PG-FLAG-{rf['name']}-{inst_name[:8]}",
                            "severity": rf['severity'],
                            "resource": f"Cloud SQL Postgres ({inst_name})",
                            "issue": f"Database flag '{rf['name']}' is set to '{val or 'Not Set'}', expected '{rf['expected']}'.",
                            "remediation": f"Configure the database flag '{rf['name']}' to enforce CIS benchmark baseline auditing protocols."
                        })
            elif 'MYSQL' in db_version:
                if flag_map.get('local_infile') != 'off':
                    findings.append({
                        "id": f"GCP-SQL-MY-FLAG-INFILE-{inst_name[:8]}",
                        "severity": "High",
                        "resource": f"Cloud SQL MySQL ({inst_name})",
                        "issue": "Database flag 'local_infile' is NOT 'off'.",
                        "remediation": "Set 'local_infile' to off to prevent arbitrary local files from being imported into the database maliciously."
                    })
                if flag_map.get('skip_show_database') != 'on':
                    findings.append({
                        "id": f"GCP-SQL-MY-FLAG-SHOWDB-{inst_name[:8]}",
                        "severity": "Low",
                        "resource": f"Cloud SQL MySQL ({inst_name})",
                        "issue": "Database flag 'skip_show_database' is NOT 'on'.",
                        "remediation": "Set 'skip_show_database' to on to prevent users from seeing databases they do not hold privileges for."
                    })
            elif 'SQLSERVER' in db_version:
                if flag_map.get('cross db ownership chaining') == 'on':
                    findings.append({
                        "id": f"GCP-SQL-MS-FLAG-CHAIN-{inst_name[:8]}",
                        "severity": "High",
                        "resource": f"Cloud SQL SQLServer ({inst_name})",
                        "issue": "Database flag 'cross db ownership chaining' is enabled.",
                        "remediation": "Disable cross db ownership chaining to restrict privileges boundary scaling across segmented databases."
                    })
                if flag_map.get('contained database authentication') == 'on':
                    findings.append({
                        "id": f"GCP-SQL-MS-FLAG-AUTH-{inst_name[:8]}",
                        "severity": "Medium",
                        "resource": f"Cloud SQL SQLServer ({inst_name})",
                        "issue": "Database flag 'contained database authentication' is enabled.",
                        "remediation": "Disable contained database authentication. It breaks the centralized isolation and lifecycle controls of SQL Server IAM."
                    })

        return {"findings": findings, "scannedCount": scanned_count}

    except Exception as error:
        print(f"[Cloud SQL] Error during SQL audit: {error}")
        return {"findings": [], "scannedCount": 0, "error": str(error)}
