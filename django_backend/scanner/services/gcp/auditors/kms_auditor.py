from googleapiclient import discovery


def audit_kms(google_auth_client, project_id):
    findings = []
    scanned_count = 0

    try:
        print(f"[KMS] Starting KMS audit for project: {project_id}")
        cloudkms = discovery.build('cloudkms', 'v1', credentials=google_auth_client, cache_discovery=False)

        try:
            locations_res = cloudkms.projects().locations().list(name=f"projects/{project_id}").execute()
            locations = locations_res.get('locations', [])
        except Exception as loc_err:
            print(f"[KMS] Failed to list locations or API not enabled: {loc_err}")
            return {"findings": findings, "scannedCount": scanned_count, "skipped": True, "reason": str(loc_err)}

        for loc in locations:
            loc_name = loc.get('name', '')
            try:
                kr_res = cloudkms.projects().locations().keyRings().list(parent=loc_name).execute()
                key_rings = kr_res.get('keyRings', [])
                scanned_count += len(key_rings)

                for kr in key_rings:
                    kr_name = kr.get('name', '')
                    kr_short = kr_name.split('/')[-1]

                    # KeyRing IAM
                    try:
                        kr_iam = cloudkms.projects().locations().keyRings().getIamPolicy(resource=kr_name).execute()
                        for b in kr_iam.get('bindings', []):
                            members = b.get('members', [])
                            if 'allUsers' in members or 'allAuthenticatedUsers' in members:
                                pub_member = next((m for m in members if m.startswith('all')), 'public')
                                findings.append({
                                    "id": f"GCP-KMS-PUBLIC-KEYRING-{kr_short[:8]}",
                                    "severity": "Critical",
                                    "resource": f"KMS KeyRing ({kr_short})",
                                    "issue": f"KeyRing is publicly accessible via '{pub_member}'.",
                                    "remediation": "Remove 'allUsers' or 'allAuthenticatedUsers' from the KeyRing's IAM policy."
                                })
                    except Exception:
                        pass

                    # CryptoKeys
                    try:
                        ck_res = cloudkms.projects().locations().keyRings().cryptoKeys().list(parent=kr_name).execute()
                        crypto_keys = ck_res.get('cryptoKeys', [])
                        scanned_count += len(crypto_keys)

                        for ck in crypto_keys:
                            ck_name = ck.get('name', '')
                            ck_short = ck_name.split('/')[-1]

                            # CryptoKey IAM
                            try:
                                ck_iam = cloudkms.projects().locations().keyRings().cryptoKeys().getIamPolicy(resource=ck_name).execute()
                                for b in ck_iam.get('bindings', []):
                                    members = b.get('members', [])
                                    if 'allUsers' in members or 'allAuthenticatedUsers' in members:
                                        pub_member = next((m for m in members if m.startswith('all')), 'public')
                                        findings.append({
                                            "id": f"GCP-KMS-PUBLIC-KEY-{ck_short[:8]}",
                                            "severity": "Critical",
                                            "resource": f"KMS CryptoKey ({ck_short})",
                                            "issue": f"CryptoKey is publicly accessible via '{pub_member}'.",
                                            "remediation": "Remove 'allUsers' or 'allAuthenticatedUsers' from the CryptoKey's IAM policy."
                                        })
                            except Exception:
                                pass

                            # Rotation
                            if ck.get('purpose') == 'ENCRYPT_DECRYPT':
                                rot_period = ck.get('rotationPeriod')
                                rotation_days = -1
                                if rot_period and 's' in rot_period:
                                    try:
                                        seconds = int(rot_period.replace('s', ''))
                                        rotation_days = seconds // (24 * 60 * 60)
                                    except Exception:
                                        pass

                                if rotation_days == -1:
                                    findings.append({
                                        "id": f"GCP-KMS-ROTATION-{ck_short[:8]}",
                                        "severity": "High",
                                        "resource": f"KMS CryptoKey ({ck_short})",
                                        "issue": "Customer Managed Key (CMK) does not have a rotation schedule configured.",
                                        "remediation": "Configure automatic rotation for this key, ensuring it rotates at least annually (every 365 days)."
                                    })
                                elif rotation_days > 365:
                                    findings.append({
                                        "id": f"GCP-KMS-ROTATION-{ck_short[:8]}",
                                        "severity": "Medium",
                                        "resource": f"KMS CryptoKey ({ck_short})",
                                        "issue": f"Key rotation period is {rotation_days} days, which exceeds the recommended annual (365 days) rotation.",
                                        "remediation": "Reduce the rotation period to 365 days or fewer."
                                    })
                    except Exception as ck_err:
                        pass
            except Exception as kr_err:
                pass

        return {"findings": findings, "scannedCount": scanned_count}

    except Exception as error:
        print(f"[KMS] Critical error during KMS audit: {error}")
        return {"findings": [], "scannedCount": 0, "error": str(error)}
