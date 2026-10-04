def audit_bigquery(bigquery_client, project_id):
    findings = []
    scanned_count = 0

    try:
        print(f"[BigQuery] Starting Dataset audit for project: {project_id}")
        datasets = list(bigquery_client.list_datasets())
        scanned_count = len(datasets)

        for dataset_ref in datasets:
            try:
                dataset = bigquery_client.get_dataset(dataset_ref.reference)
                dataset_id = dataset.dataset_id

                access_entries = dataset.access_entries or []
                public_access = []

                for entry in access_entries:
                    entity_type = getattr(entry, "entity_type", "")
                    entity_id = getattr(entry, "entity_id", "")
                    role = getattr(entry, "role", "")

                    if (
                        entity_type in ["specialGroup", "iamMember"] and
                        entity_id in ["allUsers", "allAuthenticatedUsers"]
                    ) or (
                        entity_id in ["allUsers", "allAuthenticatedUsers"]
                    ):
                        public_access.append(role)

                if public_access:
                    exposed_roles = ", ".join(public_access)
                    findings.append({
                        "id": f"GCP-BQ-PUBLIC-{dataset_id[:8]}",
                        "severity": "Critical",
                        "resource": f"BigQuery Dataset ({dataset_id})",
                        "issue": f"Dataset is publicly accessible. Exposed roles to allUsers: {exposed_roles}",
                        "remediation": "Remove 'allUsers' or 'allAuthenticatedUsers' from the dataset's access controls."
                    })

                # Dataset default CMEK
                if not dataset.default_encryption_configuration or not dataset.default_encryption_configuration.kms_key_name:
                    findings.append({
                        "id": f"GCP-BQ-DATASET-CMEK-{dataset_id[:8]}",
                        "severity": "Medium",
                        "resource": f"BigQuery Dataset ({dataset_id})",
                        "issue": "No Default Customer-Managed Encryption Key (CMEK) is configured.",
                        "remediation": "Configure a default KMS key to ensure all future tables created in this dataset are encrypted with CMEK standard."
                    })

                # Table CMEK
                try:
                    tables = list(bigquery_client.list_tables(dataset))
                    for table_ref in tables:
                        table = bigquery_client.get_table(table_ref.reference)
                        table_id = table.table_id
                        kms_key = table.encryption_configuration.kms_key_name if table.encryption_configuration else None
                        if not kms_key:
                            findings.append({
                                "id": f"GCP-BQ-TABLE-CMEK-{table_id[:8]}",
                                "severity": "High",
                                "resource": f"BigQuery Table ({dataset_id}.{table_id})",
                                "issue": "Table is NOT encrypted with a Customer-Managed Encryption Key (CMEK).",
                                "remediation": "Encrypt the table using a CMEK from Cloud KMS rather than Google-managed keys."
                            })
                except Exception as tbl_err:
                    pass

            except Exception as ds_err:
                print(f"[BigQuery] Failed to fetch dataset details: {ds_err}")

        return {"findings": findings, "scannedCount": scanned_count}

    except Exception as error:
        print(f"[BigQuery] Error during BigQuery audit: {error}")
        return {"findings": [], "scannedCount": 0, "error": str(error)}
