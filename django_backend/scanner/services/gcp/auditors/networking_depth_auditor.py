from googleapiclient import discovery


def audit_networking_depth(google_auth_client, project_id):
    findings = []
    scanned_count = 0

    try:
        compute = discovery.build('compute', 'v1', credentials=google_auth_client, cache_discovery=False)

        # 1. VPC Flow Logs
        try:
            req = compute.subnetworks().aggregatedList(project=project_id)
            while req is not None:
                resp = req.execute()
                for _, scoped_list in resp.get('items', {}).items():
                    subnets = scoped_list.get('subnetworks', [])
                    for subnet in subnets:
                        scanned_count += 1
                        if subnet.get('network', '').endswith('/default'):
                            continue

                        if not subnet.get('enableFlowLogs'):
                            findings.append({
                                "id": "GCP-NET-FLOW-LOGS-DISABLED",
                                "severity": "Low",
                                "resource": f"Subnet ({subnet.get('name')})",
                                "issue": "VPC Flow Logs are disabled for this subnetwork.",
                                "remediation": "Enable VPC Flow Logs to improve network visibility, auditing, and troubleshooting capacity."
                            })

                req = compute.subnetworks().aggregatedList_next(previous_request=req, previous_response=resp)
        except Exception:
            pass

        # 2. RDP/SSH Exposure
        try:
            fw_res = compute.firewalls().list(project=project_id).execute()
            firewalls = fw_res.get('items', [])
            scanned_count += len(firewalls)

            for fw in firewalls:
                if fw.get('direction') == 'INGRESS' and not fw.get('disabled') and fw.get('allowed'):
                    source_ranges = fw.get('sourceRanges', [])
                    if '0.0.0.0/0' in source_ranges:
                        has_rdp = any(
                            a.get('IPProtocol') == 'all' or
                            (a.get('ports') and any('3389' in str(p) for p in a.get('ports', [])))
                            for a in fw.get('allowed', [])
                        )
                        has_ssh = any(
                            a.get('IPProtocol') == 'all' or
                            (a.get('ports') and any('22' in str(p) for p in a.get('ports', [])))
                            for a in fw.get('allowed', [])
                        )

                        if has_rdp:
                            findings.append({
                                "id": "GCP-NET-PUBLIC-RDP",
                                "severity": "Critical",
                                "resource": f"Firewall Rule ({fw.get('name')})",
                                "issue": "Firewall allows RDP (port 3389) access from ANY IP address.",
                                "remediation": "Restrict RDP access to specific trusted source IP ranges or use IAP (Identity-Aware Proxy)."
                            })
                        if has_ssh:
                            findings.append({
                                "id": "GCP-NET-PUBLIC-SSH",
                                "severity": "High",
                                "resource": f"Firewall Rule ({fw.get('name')})",
                                "issue": "Firewall allows SSH (port 22) access from ANY IP address.",
                                "remediation": "Restrict SSH access to specific trusted source IP ranges or use IAP."
                            })
        except Exception:
            pass

    except Exception as err:
        pass

    return {"findings": findings, "scannedCount": scanned_count}
