from googleapiclient import discovery


def audit_gke(google_auth_client, project_id):
    findings = []
    scanned_count = 0

    try:
        container = discovery.build('container', 'v1', credentials=google_auth_client, cache_discovery=False)
        res = container.projects().locations().clusters().list(
            parent=f"projects/{project_id}/locations/-"
        ).execute()

        clusters = res.get('clusters', [])
        scanned_count = len(clusters)

        for cluster in clusters:
            cluster_id = cluster.get('name', 'unknown')
            private_cfg = cluster.get('privateClusterConfig', {})
            is_public = not private_cfg.get('enablePrivateNodes')
            auth_nets = cluster.get('masterAuthorizedNetworksConfig', {})
            has_auth_networks = auth_nets.get('enabled', False)

            # 1. Control plane exposure
            if is_public and not has_auth_networks:
                findings.append({
                    "id": "GCP-GKE-PUBLIC-ENDPOINT",
                    "severity": "Critical",
                    "resource": f"GKE Cluster ({cluster_id})",
                    "issue": "GKE control plane has a public endpoint with no authorized networks configured. Anyone can attempt to reach the API server.",
                    "remediation": "Enable Private Nodes and configure Master Authorized Networks to restrict access to the control plane."
                })
            elif is_public:
                findings.append({
                    "id": "GCP-GKE-PUBLIC-ENDPOINT-RESTRICTED",
                    "severity": "Medium",
                    "resource": f"GKE Cluster ({cluster_id})",
                    "issue": "GKE control plane endpoint is public, although protected by authorized networks.",
                    "remediation": "Consider using a private endpoint to completely isolate the control plane from the internet."
                })

            # 2. Legacy ABAC
            if cluster.get('legacyAbac', {}).get('enabled'):
                findings.append({
                    "id": "GCP-GKE-LEGACY-ABAC",
                    "severity": "High",
                    "resource": f"GKE Cluster ({cluster_id})",
                    "issue": "Legacy ABAC / Attribute-Based Access Control is enabled. This bypasses RBAC and can lead to excessive privileges.",
                    "remediation": "Disable Legacy ABAC and use Kubernetes RBAC for more granular security."
                })

            # 3. Workload Identity
            if not cluster.get('workloadIdentityConfig', {}).get('workloadPool'):
                findings.append({
                    "id": "GCP-GKE-WORKLOAD-IDENTITY-DISABLED",
                    "severity": "High",
                    "resource": f"GKE Cluster ({cluster_id})",
                    "issue": "Workload Identity is not enabled. Pods may be using Compute Engine default service accounts with too much power.",
                    "remediation": "Enable Workload Identity to securely map Kubernetes service accounts to GCP service accounts."
                })

            # 4. Shielded Nodes
            if not cluster.get('shieldedNodes', {}).get('enabled'):
                findings.append({
                    "id": "GCP-GKE-SHIELDED-NODES-DISABLED",
                    "severity": "Medium",
                    "resource": f"GKE Cluster ({cluster_id})",
                    "issue": "Shielded GKE Nodes are disabled. This leaves nodes vulnerable to boot-level rootkits or persistence.",
                    "remediation": "Enable Shielded GKE Nodes to provide strong, verifiable node identity and integrity."
                })

            # 5. Binary Authorization
            if not cluster.get('binaryAuthorization', {}).get('enabled'):
                findings.append({
                    "id": "GCP-GKE-BINARY-AUTH-DISABLED",
                    "severity": "Low",
                    "resource": f"GKE Cluster ({cluster_id})",
                    "issue": "Binary Authorization is disabled. Untrusted images could be deployed to the cluster.",
                    "remediation": "Enable Binary Authorization to ensure only signed, trustworthy images are deployed."
                })

    except Exception as err:
        pass

    return {"findings": findings, "scannedCount": scanned_count}
