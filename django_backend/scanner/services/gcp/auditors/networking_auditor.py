from googleapiclient import discovery


def audit_networking(google_auth_client, project_id):
    findings = []
    scanned_count = 0

    try:
        print(f"[Networking] Starting VPC / Firewall audit for project: {project_id}")
        compute = discovery.build('compute', 'v1', credentials=google_auth_client, cache_discovery=False)

        # 1. VPC Networks
        try:
            net_res = compute.networks().list(project=project_id).execute()
            networks = net_res.get('items', [])
            scanned_count += len(networks)

            for net in networks:
                net_name = net.get('name', 'unknown')
                if net_name == 'default':
                    findings.append({
                        "id": f"GCP-NET-DEFAULT-{project_id[:8]}",
                        "severity": "Medium",
                        "resource": "VPC Network (default)",
                        "issue": "The 'default' network exists in the project.",
                        "remediation": "Delete the default network to ensure all network configurations are explicitly created with least privilege and custom subnets."
                    })

                is_legacy = (not net.get('autoCreateSubnetworks')) and (not net.get('subnetworks')) and net.get('IPv4Range')
                if is_legacy:
                    findings.append({
                        "id": f"GCP-NET-LEGACY-{net_name[:8]}",
                        "severity": "High",
                        "resource": f"VPC Network ({net_name})",
                        "issue": "Legacy Network detected.",
                        "remediation": "Migrate to Subnet networks. Legacy networks have a single global IP range and cannot utilize regional subnets or advanced cloud features."
                    })
        except Exception as net_err:
            print(f"[Networking] Failed to list VPCs: {net_err}")

        # 2. Firewalls
        try:
            fw_res = compute.firewalls().list(project=project_id).execute()
            firewalls = fw_res.get('items', [])
            scanned_count += len(firewalls)

            for fw in firewalls:
                if fw.get('direction') == 'INGRESS' and not fw.get('denied') and not fw.get('disabled'):
                    source_ranges = fw.get('sourceRanges', [])
                    allows_all = '0.0.0.0/0' in source_ranges

                    if allows_all and fw.get('allowed'):
                        for allowed in fw.get('allowed', []):
                            proto = allowed.get('IPProtocol', '')
                            ports = allowed.get('ports', [])

                            # SSH 22
                            if (proto == 'all') or (proto == 'tcp' and any(p == '22' or (p.isdigit() and int(p) == 22) or '22' in p for p in ports)):
                                findings.append({
                                    "id": f"GCP-FW-OPEN-SSH-{fw.get('name', '')[:8]}",
                                    "severity": "Critical",
                                    "resource": f"Firewall Rule ({fw.get('name')})",
                                    "issue": "Firewall rule allows SSH (port 22) access from anywhere (0.0.0.0/0) on the internet.",
                                    "remediation": "Restrict SSH access to specific known IP addresses or utilize Identity-Aware Proxy (IAP) for TCP forwarding."
                                })

                            # RDP 3389
                            if (proto == 'all') or (proto == 'tcp' and any(p == '3389' or (p.isdigit() and int(p) == 3389) or '3389' in p for p in ports)):
                                findings.append({
                                    "id": f"GCP-FW-OPEN-RDP-{fw.get('name', '')[:8]}",
                                    "severity": "Critical",
                                    "resource": f"Firewall Rule ({fw.get('name')})",
                                    "issue": "Firewall rule allows RDP (port 3389) access from anywhere (0.0.0.0/0) on the internet.",
                                    "remediation": "Restrict RDP access to specific known IP addresses or utilize Identity-Aware Proxy (IAP) for TCP forwarding."
                                })

                            # Database Ports
                            db_ports = ['3306', '5432', '1433', '27017', '6379']
                            for dp in db_ports:
                                if (proto == 'all') or (proto == 'tcp' and any(p == dp or dp in p for p in ports)):
                                    findings.append({
                                        "id": f"GCP-FW-OPEN-DB-{dp}-{fw.get('name', '')[:8]}",
                                        "severity": "Critical",
                                        "resource": f"Firewall Rule ({fw.get('name')})",
                                        "issue": f"Firewall rule allows direct database port ({dp}) access from anywhere (0.0.0.0/0).",
                                        "remediation": "Never expose infrastructure databases directly to the public internet."
                                    })
        except Exception as fw_err:
            print(f"[Networking] Failed to list Firewalls: {fw_err}")

        # 3. Subnetworks (VPC Flow Logs & Private Google Access)
        try:
            req = compute.subnetworks().aggregatedList(project=project_id)
            while req is not None:
                resp = req.execute()
                for region_scope, scoped_list in resp.get('items', {}).items():
                    subnets = scoped_list.get('subnetworks', [])
                    for subnet in subnets:
                        scanned_count += 1
                        sub_name = subnet.get('name', 'unknown')
                        region_name = subnet.get('region', '').split('/')[-1]

                        if not subnet.get('enableFlowLogs'):
                            findings.append({
                                "id": f"GCP-NET-FLOWLOGS-{sub_name[:8]}",
                                "severity": "Medium",
                                "resource": f"Subnetwork ({sub_name}) in {region_name}",
                                "issue": "VPC Flow Logs are not enabled for this subnetwork.",
                                "remediation": "Enable VPC Flow Logs for all subnets to monitor traffic, aid in forensic investigations, and detect anomalous network behavior."
                            })

                        if not subnet.get('privateIpGoogleAccess'):
                            findings.append({
                                "id": f"GCP-NET-PGA-{sub_name[:8]}",
                                "severity": "High",
                                "resource": f"Subnetwork ({sub_name}) in {region_name}",
                                "issue": "Private Google Access is NOT enabled.",
                                "remediation": "Enable Private Google Access so VMs can reach Google APIs internally without routing across the public internet."
                            })

                req = compute.subnetworks().aggregatedList_next(previous_request=req, previous_response=resp)
        except Exception as sn_err:
            print(f"[Networking] Failed to list Subnetworks: {sn_err}")

        # 4. Backend Services (Load Balancers)
        try:
            req = compute.backendServices().aggregatedList(project=project_id)
            while req is not None:
                resp = req.execute()
                for scope, scoped_list in resp.get('items', {}).items():
                    backend_services = scoped_list.get('backendServices', [])
                    for svc in backend_services:
                        scanned_count += 1
                        svc_name = svc.get('name', 'unknown')
                        scheme = svc.get('loadBalancingScheme')

                        if scheme in ['EXTERNAL', 'INTERNAL_MANAGED', 'EXTERNAL_MANAGED']:
                            log_cfg = svc.get('logConfig', {})
                            if not log_cfg.get('enable'):
                                findings.append({
                                    "id": f"GCP-NET-LBLOG-{svc_name[:8]}",
                                    "severity": "Medium",
                                    "resource": f"Load Balancer Service ({svc_name})",
                                    "issue": "Logging is NOT enabled for the HTTP(S) Load Balancer (Backend).",
                                    "remediation": "Enable logging on backend services to troubleshoot issues and monitor traffic patterns."
                                })

                req = compute.backendServices().aggregatedList_next(previous_request=req, previous_response=resp)
        except Exception as bs_err:
            print(f"[Networking] Failed to list Backend Services: {bs_err}")

        return {"findings": findings, "scannedCount": scanned_count}

    except Exception as error:
        print(f"[Networking] Error during Networking audit: {error}")
        return {"findings": [], "scannedCount": 0, "error": str(error)}
