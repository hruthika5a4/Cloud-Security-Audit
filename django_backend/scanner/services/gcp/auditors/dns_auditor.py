from googleapiclient import discovery


def audit_dns(google_auth_client, project_id):
    findings = []
    scanned_count = 0

    try:
        print(f"[Cloud DNS] Starting Cloud DNS audit for project: {project_id}")
        dns = discovery.build('dns', 'v1', credentials=google_auth_client, cache_discovery=False)

        try:
            zones_res = dns.managedZones().list(project=project_id).execute()
            zones = zones_res.get('managedZones', [])
        except Exception as dns_err:
            print(f"[Cloud DNS] Failed to list managed zones or API not enabled: {dns_err}")
            return {"findings": findings, "scannedCount": scanned_count}

        scanned_count += len(zones)

        for zone in zones:
            zone_name = zone.get('name', 'unknown')
            dnssec_config = zone.get('dnssecConfig', {})

            if not dnssec_config or dnssec_config.get('state') != 'on':
                findings.append({
                    "id": f"GCP-DNS-DNSSEC-{zone_name[:8]}",
                    "severity": "High",
                    "resource": f"Cloud DNS Zone ({zone_name})",
                    "issue": "DNSSEC is not enabled for this managed zone.",
                    "remediation": "Enable DNSSEC to protect your domains against spoofing and cache poisoning."
                })
            else:
                key_specs = dnssec_config.get('defaultKeySpecs', [])
                for key in key_specs:
                    algo = str(key.get('algorithm', '')).lower()
                    if 'rsasha1' in algo:
                        is_ksk = key.get('keyType') == 'keySigning'
                        key_type_str = 'Key Signing Key (KSK)' if is_ksk else 'Zone Signing Key (ZSK)'
                        tag = 'KSK' if is_ksk else 'ZSK'
                        findings.append({
                            "id": f"GCP-DNS-RSASHA1-{tag}-{zone_name[:8]}",
                            "severity": "Critical",
                            "resource": f"Cloud DNS Zone ({zone_name})",
                            "issue": f"DNSSEC {key_type_str} is utilizing the weak RSASHA1 algorithm.",
                            "remediation": "Upgrade the DNSSEC signing algorithm to RSASHA256, RSASHA512, or ECDSA algorithms which offer much stronger cryptographic strength."
                        })

        # DNS Policies Logging
        try:
            policies_res = dns.policies().list(project=project_id).execute()
            policies = policies_res.get('policies', [])
            scanned_count += len(policies)

            if len(policies) == 0:
                findings.append({
                    "id": f"GCP-DNS-LOG-MISSING-{project_id[:8]}",
                    "severity": "Low",
                    "resource": "Cloud DNS Policies",
                    "issue": "No Cloud DNS Policies exist, meaning DNS query logging is not enabled for VPC networks.",
                    "remediation": "Create a DNS Policy with 'enableLogging' set to true and attach it to your VPC networks."
                })

            for pol in policies:
                if not pol.get('enableLogging'):
                    pol_name = pol.get('name', 'unknown')
                    findings.append({
                        "id": f"GCP-DNS-LOG-{pol_name[:8]}",
                        "severity": "Low",
                        "resource": f"Cloud DNS Policy ({pol_name})",
                        "issue": "Cloud DNS query logging is NOT enabled.",
                        "remediation": "Turn on DNS query logging for the policy to monitor name resolution activities."
                    })
        except Exception:
            pass

        return {"findings": findings, "scannedCount": scanned_count}

    except Exception as error:
        print(f"[Cloud DNS] Critical error during DNS audit: {error}")
        return {"findings": [], "scannedCount": 0, "error": str(error)}
