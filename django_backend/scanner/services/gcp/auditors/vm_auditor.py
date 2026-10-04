from googleapiclient import discovery


def audit_vms(google_auth_client, project_id):
    findings = []
    scanned_count = 0

    try:
        print(f"[Compute Engine] Starting VM audit for project: {project_id}")
        compute = discovery.build('compute', 'v1', credentials=google_auth_client, cache_discovery=False)

        # 1. Project-wide metadata settings
        try:
            proj_res = compute.projects().get(project=project_id).execute()
            common_metadata = proj_res.get('commonInstanceMetadata', {}).get('items', [])

            block_ssh = next((item for item in common_metadata if item.get('key') == 'block-project-ssh-keys'), None)
            if not block_ssh or str(block_ssh.get('value', '')).lower() != 'true':
                findings.append({
                    "id": "GCP-VM-PROJ-SSH",
                    "severity": "High",
                    "resource": "Compute Engine (Project Level)",
                    "issue": '"Block Project-Wide SSH Keys" is NOT enabled.',
                    "remediation": "Enable block-project-ssh-keys at the project metadata level to prevent users from using legacy SSH keys across instances."
                })

            enable_oslogin = next((item for item in common_metadata if item.get('key') == 'enable-oslogin'), None)
            if not enable_oslogin or str(enable_oslogin.get('value', '')).lower() != 'true':
                findings.append({
                    "id": "GCP-VM-PROJ-OSLOGIN",
                    "severity": "Medium",
                    "resource": "Compute Engine (Project Level)",
                    "issue": "OS Login is NOT enabled for the project.",
                    "remediation": "Enable OS Login to manage SSH access centrally through IAM policies rather than SSH keys."
                })
        except Exception as pe:
            print(f"[Compute Engine] Failed to fetch project metadata: {pe}")

        # 2. Aggregated instances list
        try:
            request = compute.instances().aggregatedList(project=project_id)
            while request is not None:
                response = request.execute()
                items = response.get('items', {})

                for zone_scope, scoped_list in items.items():
                    instances = scoped_list.get('instances', [])
                    for inst in instances:
                        scanned_count += 1
                        inst_name = inst.get('name', 'unknown')

                        # Target 1: Public IP
                        has_public_ip = False
                        for iface in inst.get('networkInterfaces', []):
                            for config in iface.get('accessConfigs', []):
                                if config.get('natIP') or config.get('type') == 'ONE_TO_ONE_NAT':
                                    has_public_ip = True
                                    break
                        if has_public_ip:
                            findings.append({
                                "id": f"GCP-VM-PUBLIC-IP-{inst_name[:8]}",
                                "severity": "High",
                                "resource": f"Compute Instance ({inst_name})",
                                "issue": "Instance possesses a Public IP address.",
                                "remediation": "Remove external IP addresses and use Identity-Aware Proxy (IAP) or Cloud NAT for external communications."
                            })

                        # Target 2: IP Forwarding
                        if inst.get('canIpForward'):
                            findings.append({
                                "id": f"GCP-VM-IP-FWD-{inst_name[:8]}",
                                "severity": "High",
                                "resource": f"Compute Instance ({inst_name})",
                                "issue": "IP Forwarding is enabled.",
                                "remediation": "Disable IP Forwarding unless the instance strictly acts as a NAT gateway or router."
                            })

                        # Target 3: Default Service Account
                        sas = inst.get('serviceAccounts', [])
                        if sas:
                            sa_email = sas[0].get('email', '')
                            if '-compute@developer.gserviceaccount.com' in sa_email:
                                findings.append({
                                    "id": f"GCP-VM-DEF-SA-{inst_name[:8]}",
                                    "severity": "Medium",
                                    "resource": f"Compute Instance ({inst_name})",
                                    "issue": "Instance is configured to use the default Compute Engine service account.",
                                    "remediation": "Create a dedicated, least-privilege service account specifically for this workload and assign it to the instance."
                                })

                                scopes = sas[0].get('scopes', [])
                                if 'https://www.googleapis.com/auth/cloud-platform' in scopes:
                                    findings.append({
                                        "id": f"GCP-VM-DEF-SA-FULL-{inst_name[:8]}",
                                        "severity": "High",
                                        "resource": f"Compute Instance ({inst_name})",
                                        "issue": "Instance is configured to use the default Compute Engine service account with full access to all Cloud APIs.",
                                        "remediation": "Limit the access scopes of the instance and explicitly assign a least-privilege service account."
                                    })

                        # Target 4: Shielded VM Secure Boot
                        shielded = inst.get('shieldedInstanceConfig', {})
                        if not shielded.get('enableSecureBoot'):
                            findings.append({
                                "id": f"GCP-VM-SHIELDED-{inst_name[:8]}",
                                "severity": "Low",
                                "resource": f"Compute Instance ({inst_name})",
                                "issue": "Secure Boot (Shielded VM) is NOT enabled.",
                                "remediation": "Launch instances with Shielded VM features enabled to prevent rootkits and boot-level malware."
                            })

                        # Target 5: Serial Port Connecting
                        inst_metadata = inst.get('metadata', {}).get('items', [])
                        serial_enable = next((item for item in inst_metadata if item.get('key') == 'serial-port-enable'), None)
                        if serial_enable and str(serial_enable.get('value', '')).lower() == 'true':
                            findings.append({
                                "id": f"GCP-VM-SERIAL-{inst_name[:8]}",
                                "severity": "Medium",
                                "resource": f"Compute Instance ({inst_name})",
                                "issue": "Connecting to serial ports is enabled for this instance.",
                                "remediation": "Disable 'Enable connecting to serial ports' on the VM instance unless actively troubleshooting."
                            })

                        # Target 6: Disks Encrypted with CMEK
                        for disk in inst.get('disks', []):
                            key_name = disk.get('diskEncryptionKey', {}).get('kmsKeyName')
                            device_name = disk.get('deviceName', 'unknown')
                            if not key_name:
                                findings.append({
                                    "id": f"GCP-VM-DISK-CMEK-{inst_name[:8]}",
                                    "severity": "Low",
                                    "resource": f"Compute Instance ({inst_name}) Disk ({device_name})",
                                    "issue": "Disk is not encrypted with a Customer-Managed Encryption Key (CMEK).",
                                    "remediation": "Use Customer-Managed Encryption Keys (CMEK) to encrypt disks if your compliance requirements mandate controlling the encryption keys."
                                })

                        # Target 7: Confidential Computing
                        confidential = inst.get('confidentialInstanceConfig', {})
                        if not confidential.get('enableConfidentialCompute'):
                            findings.append({
                                "id": f"GCP-VM-CONFIDENTIAL-{inst_name[:8]}",
                                "severity": "Low",
                                "resource": f"Compute Instance ({inst_name})",
                                "issue": "Confidential Computing is NOT enabled.",
                                "remediation": "Enable Confidential Computing to encrypt data in-use. Note: Requires specific machine types."
                            })

                        # Target 8: Deletion Protection
                        if not inst.get('deletionProtection'):
                            findings.append({
                                "id": f"GCP-VM-DEL-PROT-{inst_name[:8]}",
                                "severity": "Medium",
                                "resource": f"Compute Instance ({inst_name})",
                                "issue": "Deletion protection is NOT enabled.",
                                "remediation": "Enable deletion protection to prevent accidental termination of critical instances."
                            })

                        # Target 9: Preemptible
                        if inst.get('scheduling', {}).get('preemptible'):
                            findings.append({
                                "id": f"GCP-VM-PREEMPT-{inst_name[:8]}",
                                "severity": "Low",
                                "resource": f"Compute Instance ({inst_name})",
                                "issue": "Instance is configured as Preemptible.",
                                "remediation": "Ensure preemptible instances are strictly used for fault-tolerant batch workloads, not production services requiring high availability."
                            })

                        # Target 10: Instance metadata overrides
                        block_inst = next((item for item in inst_metadata if item.get('key') == 'block-project-ssh-keys'), None)
                        if block_inst and str(block_inst.get('value', '')).lower() == 'false':
                            findings.append({
                                "id": f"GCP-VM-INST-SSH-{inst_name[:8]}",
                                "severity": "High",
                                "resource": f"Compute Instance ({inst_name})",
                                "issue": "Instance explicitly allows project-wide SSH keys.",
                                "remediation": "Remove the overriding metadata 'block-project-ssh-keys=false' to honor project-wide SSH key blocking protocols."
                            })

                        oslogin_inst = next((item for item in inst_metadata if item.get('key') == 'enable-oslogin'), None)
                        if oslogin_inst and str(oslogin_inst.get('value', '')).lower() == 'false':
                            findings.append({
                                "id": f"GCP-VM-INST-OSLOGIN-{inst_name[:8]}",
                                "severity": "Medium",
                                "resource": f"Compute Instance ({inst_name})",
                                "issue": "Instance explicitly disables OS Login.",
                                "remediation": "Remove the overriding metadata 'enable-oslogin=false' to honor project-wide centralized identity access control."
                            })

                request = compute.instances().aggregatedList_next(previous_request=request, previous_response=response)
        except Exception as inst_err:
            print(f"[Compute Engine] Failed to list instances: {inst_err}")

        return {"findings": findings, "scannedCount": scanned_count}

    except Exception as error:
        print(f"[Compute Engine] Error during VM audit: {error}")
        return {"findings": [], "scannedCount": 0, "error": str(error)}
