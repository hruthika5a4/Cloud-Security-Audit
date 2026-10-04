from googleapiclient import discovery


def audit_dataproc(google_auth_client, project_id):
    findings = []
    scanned_count = 0

    try:
        print(f"[Dataproc] Starting Dataproc cluster audit for project: {project_id}")
        dataproc = discovery.build('dataproc', 'v1', credentials=google_auth_client, cache_discovery=False)
        compute = discovery.build('compute', 'v1', credentials=google_auth_client, cache_discovery=False)

        regions = []
        try:
            regions_res = compute.regions().list(project=project_id).execute()
            regions = [r.get('name') for r in regions_res.get('items', [])]
        except Exception:
            regions = ['global', 'us-central1', 'us-east1', 'europe-west1', 'asia-southeast1']

        for region in regions:
            try:
                res = dataproc.projects().regions().clusters().list(
                    projectId=project_id,
                    region=region
                ).execute()

                clusters = res.get('clusters', [])
                scanned_count += len(clusters)

                for cluster in clusters:
                    cluster_name = cluster.get('clusterName', 'unknown')
                    config = cluster.get('config', {})
                    enc_config = config.get('encryptionConfig', {})

                    if not enc_config or not enc_config.get('gcePdKmsKeyName'):
                        findings.append({
                            "id": f"GCP-DATAPROC-CMEK-{cluster_name[:8]}",
                            "severity": "High",
                            "resource": f"Dataproc Cluster ({cluster_name}) in {region}",
                            "issue": "Dataproc cluster is NOT encrypted using a Customer-Managed Encryption Key (CMEK).",
                            "remediation": "Configure the cluster with a CMEK (encryptionConfig.gcePdKmsKeyName) to encrypt the data disks attached to the cluster nodes securely."
                        })
            except Exception as err:
                if 'API has not been used' in str(err):
                    break

        return {"findings": findings, "scannedCount": scanned_count}

    except Exception as error:
        print(f"[Dataproc] Error during Dataproc audit: {error}")
        return {"findings": [], "scannedCount": 0, "error": str(error)}
