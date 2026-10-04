from googleapiclient import discovery


def audit_serverless(google_auth_client, project_id):
    findings = []
    scanned_count = 0

    try:
        cloud_run = discovery.build('run', 'v1', credentials=google_auth_client, cache_discovery=False)
        cloud_functions = discovery.build('cloudfunctions', 'v1', credentials=google_auth_client, cache_discovery=False)

        # 1. Cloud Run
        try:
            run_res = cloud_run.projects().locations().services().list(
                parent=f"projects/{project_id}/locations/-"
            ).execute()

            services = run_res.get('items', [])
            scanned_count += len(services)

            for svc in services:
                meta = svc.get('metadata', {})
                name = meta.get('name', 'unknown')
                region = meta.get('labels', {}).get('cloud.googleapis.com/location', 'unknown')
                ingress = meta.get('annotations', {}).get('run.googleapis.com/ingress', 'all')

                is_public = False
                try:
                    pol_res = cloud_run.projects().locations().services().getIamPolicy(
                        resource=f"projects/{project_id}/locations/{region}/services/{name}"
                    ).execute()
                    bindings = pol_res.get('bindings', [])
                    for b in bindings:
                        role = b.get('role', '')
                        members = b.get('members', [])
                        if role in ['roles/run.invoker', 'roles/viewer']:
                            if 'allUsers' in members or 'allAuthenticatedUsers' in members:
                                is_public = True
                                break
                except Exception:
                    pass

                if is_public:
                    findings.append({
                        "id": "GCP-CLOUDRUN-PUBLIC-ACCESS",
                        "severity": "High",
                        "resource": f"Cloud Run Service ({name})",
                        "issue": "Service is accessible to unauthenticated users or all authenticated users.",
                        "remediation": 'Remove "allUsers" or "allAuthenticatedUsers" from the IAM invoker role for this service.'
                    })

                if ingress == 'all':
                    findings.append({
                        "id": "GCP-CLOUDRUN-ALLOW-ALL-INGRESS",
                        "severity": "Medium",
                        "resource": f"Cloud Run Service ({name})",
                        "issue": 'Ingress settings are set to "Allow All", meaning it can be reached directly via its default URL.',
                        "remediation": 'Change ingress to "Internal" or "Internal and Cloud Load Balancing" if appropriate for your architecture.'
                    })
        except Exception:
            pass

        # 2. Cloud Functions
        try:
            fn_res = cloud_functions.projects().locations().functions().list(
                parent=f"projects/{project_id}/locations/-"
            ).execute()

            functions = fn_res.get('functions', [])
            scanned_count += len(functions)

            for fn in functions:
                name = fn.get('name', '').split('/')[-1]
                ingress = fn.get('ingressSettings', 'ALLOW_ALL')

                if ingress == 'ALLOW_ALL':
                    findings.append({
                        "id": "GCP-FUNCTION-ALLOW-ALL-INGRESS",
                        "severity": "Medium",
                        "resource": f"Cloud Function ({name})",
                        "issue": 'Ingress settings are set to "Allow All".',
                        "remediation": 'Restrict ingress to "internal-only" or use an API Gateway/Load Balancer.'
                    })

                sa_email = fn.get('serviceAccountEmail', '')
                if 'compute@developer.gserviceaccount.com' in sa_email:
                    findings.append({
                        "id": "GCP-FUNCTION-DEFAULT-SA",
                        "severity": "Medium",
                        "resource": f"Cloud Function ({name})",
                        "issue": 'Function is using the default Compute Engine service account, which often has broad "Editor" permissions.',
                        "remediation": "Create a dedicated service account with minimal required permissions for this function."
                    })
        except Exception:
            pass

    except Exception as err:
        print(f"[Serverless Auditor] Error: {err}")

    return {"findings": findings, "scannedCount": scanned_count}
