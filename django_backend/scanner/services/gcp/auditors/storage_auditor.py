def audit_storage_buckets(storage_client, project_id):
    findings = []
    scanned_count = 0

    try:
        print(f"[Storage] Starting bucket audit for project: {project_id}")
        buckets = list(storage_client.list_buckets())
        print(f"[Storage] Found {len(buckets)} buckets.")

        for bucket in buckets:
            scanned_count += 1
            bucket_name = bucket.name

            try:
                bucket.reload()
                policy = bucket.get_iam_policy(requested_policy_version=3)

                # Target 1: Publicly accessible bucket
                bindings = policy.bindings if hasattr(policy, "bindings") else []
                public_bindings = []
                for b in bindings:
                    members = b.get("members", set())
                    if "allUsers" in members or "allAuthenticatedUsers" in members:
                        public_bindings.append(b)

                if public_bindings:
                    exposed_roles = ", ".join(b.get("role", "") for b in public_bindings)
                    findings.append({
                        "id": f"GCP-STORAGE-PUBLIC-{bucket_name[:8]}",
                        "severity": "Critical",
                        "resource": f"Storage Bucket ({bucket_name})",
                        "issue": f"Bucket is publicly accessible. Exposed roles: {exposed_roles}",
                        "remediation": "Remove 'allUsers' and 'allAuthenticatedUsers' from the IAM policy."
                    })

                # Target 2: Uniform Bucket-Level Access disabled
                ubla = bucket.iam_configuration.uniform_bucket_level_access_enabled if bucket.iam_configuration else False
                if not ubla:
                    findings.append({
                        "id": f"GCP-STORAGE-UBLA-{bucket_name[:8]}",
                        "severity": "Medium",
                        "resource": f"Storage Bucket ({bucket_name})",
                        "issue": "Uniform Bucket-Level Access (UBLA) is NOT enabled.",
                        "remediation": "Enable UBLA to unify and simplify access control to prevent accidental ACL misconfigurations."
                    })

                # Target 3: Public Access Prevention (PAP)
                pap = bucket.iam_configuration.public_access_prevention if bucket.iam_configuration else None
                if pap != "enforced":
                    findings.append({
                        "id": f"GCP-STORAGE-PAP-{bucket_name[:8]}",
                        "severity": "High",
                        "resource": f"Storage Bucket ({bucket_name})",
                        "issue": "Public Access Prevention is NOT enforced.",
                        "remediation": "Enforce Public Access Prevention to guarantee that public access to the bucket and its objects is unconditionally blocked."
                    })

                # Target 4: Object Versioning
                if not bucket.versioning_enabled:
                    findings.append({
                        "id": f"GCP-STORAGE-VERS-{bucket_name[:8]}",
                        "severity": "Low",
                        "resource": f"Storage Bucket ({bucket_name})",
                        "issue": "Object Versioning is NOT enabled.",
                        "remediation": "Enable object versioning to protect data against accidental deletion or modification (ransomware/malware recovery)."
                    })

                # Target 5: Data Access Logging
                if not (bucket.logging and bucket.logging.get("logBucket")):
                    findings.append({
                        "id": f"GCP-STORAGE-LOG-{bucket_name[:8]}",
                        "severity": "Low",
                        "resource": f"Storage Bucket ({bucket_name})",
                        "issue": "Cloud Storage Access Logging is NOT configured.",
                        "remediation": "Configure bucket logging to maintain an audit trail of access usage."
                    })

                # Target 6: CMEK
                cmek = bucket.default_kms_key_name
                if not cmek:
                    findings.append({
                        "id": f"GCP-STORAGE-CMEK-{bucket_name[:8]}",
                        "severity": "Medium",
                        "resource": f"Storage Bucket ({bucket_name})",
                        "issue": "Customer-Managed Encryption Key (CMEK) is NOT configured as default.",
                        "remediation": "Use CMEK instead of Google-managed keys to maintain full centralized control over decryption keys."
                    })

            except Exception as iam_err:
                print(f"[Storage] Failed to inspect bucket {bucket_name}: {iam_err}")

        return {"findings": findings, "scannedCount": scanned_count}

    except Exception as error:
        print(f"[Storage] Critical error during bucket audit: {error}")
        return {"findings": [], "scannedCount": 0, "error": str(error)}
