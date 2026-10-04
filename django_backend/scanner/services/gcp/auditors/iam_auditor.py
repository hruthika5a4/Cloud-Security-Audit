import re
import datetime
from googleapiclient import discovery


def audit_iam(google_auth_client, project_id):
    findings = []
    scanned_count = 0

    try:
        print(f"[IAM] Starting IAM audit for project: {project_id}")
        iam = discovery.build('iam', 'v1', credentials=google_auth_client, cache_discovery=False)
        crm = discovery.build('cloudresourcemanager', 'v1', credentials=google_auth_client, cache_discovery=False)

        # 1. Project-Level IAM Policy
        try:
            policy_res = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
            bindings = policy_res.get('bindings', [])
            member_roles = {}

            for binding in bindings:
                role = binding.get('role', '')
                members = binding.get('members', [])

                for member in members:
                    if member not in member_roles:
                        member_roles[member] = set()
                    member_roles[member].add(role)

                # Check admin/owner privileges on service accounts & users
                if role in ['roles/owner', 'roles/editor']:
                    for sa in [m for m in members if m.startswith('serviceAccount:')]:
                        sa_clean = sa.replace('serviceAccount:', '')
                        findings.append({
                            "id": f"GCP-IAM-SA-ADMIN-{sa_clean[:8]}",
                            "severity": "High",
                            "resource": f"IAM Policy (Project: {project_id})",
                            "issue": f"Service Account {sa_clean} has primitive admin privileges ({role}).",
                            "remediation": "Apply the Principle of Least Privilege by removing primitive roles and replacing them with specific predefined roles."
                        })

                    if role == 'roles/owner':
                        for user in [m for m in members if m.startswith('user:')]:
                            user_clean = user.replace('user:', '')
                            findings.append({
                                "id": f"GCP-IAM-USER-OWNER-{user_clean[:8]}",
                                "severity": "Medium",
                                "resource": f"IAM Policy (Project: {project_id})",
                                "issue": f"User {user_clean} possesses the sweeping primitive 'roles/owner' role.",
                                "remediation": "Assign specific predefined responsibilities rather than permanent primitive ownership."
                            })

                # Check SA User / Token Creator at project level
                if role in ['roles/iam.serviceAccountUser', 'roles/iam.serviceAccountTokenCreator']:
                    for user in [m for m in members if m.startswith('user:')]:
                        user_clean = user.replace('user:', '')
                        findings.append({
                            "id": f"GCP-IAM-PROJECT-TOKEN-{user_clean[:8]}",
                            "severity": "Medium",
                            "resource": f"IAM Policy (Project: {project_id})",
                            "issue": f"User {user_clean} has {role} at the Project Level.",
                            "remediation": "Remove the role from the project level. Assign it specifically to the individual Service Account the user needs access to."
                        })

            # Separation of Duties checks
            for member, roles in member_roles.items():
                member_clean = re.sub(r'^[a-zA-Z]+:', '', member)
                member_id = re.sub(r'[^a-zA-Z0-9]', '', member)[:8]

                # KMS SoD
                if 'roles/cloudkms.admin' in roles and (
                    'roles/cloudkms.cryptoKeyEncrypterDecrypter' in roles or
                    'roles/owner' in roles or
                    'roles/editor' in roles
                ):
                    findings.append({
                        "id": f"GCP-IAM-KMS-SOD-{member_id}",
                        "severity": "High",
                        "resource": f"IAM Policy (Project: {project_id})",
                        "issue": f"Identity {member_clean} has both KMS Admin and Encrypter/Decrypter (or primitive Admin) roles, violating Separation of Duties.",
                        "remediation": "Remove either the administrative or data access role from this identity. Use distinct accounts for KMS administration and usage."
                    })

                # Network vs Compute SoD
                if 'roles/compute.networkAdmin' in roles and 'roles/iam.serviceAccountUser' in roles:
                    findings.append({
                        "id": f"GCP-IAM-NET-SOD-{member_id}",
                        "severity": "Medium",
                        "resource": f"IAM Policy (Project: {project_id})",
                        "issue": f"Identity {member_clean} holds both Network Admin and Service Account User capabilities.",
                        "remediation": "Isolate network definitions from compute deployment identities to restrict potential lateral escalation routes."
                    })

        except Exception as pol_err:
            print(f"[IAM] Failed to get project IAM policy: {pol_err}")

        # 2. Service Account Keys
        try:
            sa_res = iam.projects().serviceAccounts().list(name=f"projects/{project_id}").execute()
            service_accounts = sa_res.get('accounts', [])
            scanned_count += len(service_accounts)

            now = datetime.datetime.now(datetime.timezone.utc)

            for sa in service_accounts:
                sa_name = sa.get('name', '')
                sa_email = sa.get('email', '')

                try:
                    keys_res = iam.projects().serviceAccounts().keys().list(
                        name=sa_name,
                        keyTypes=['USER_MANAGED']
                    ).execute()

                    user_managed_keys = keys_res.get('keys', [])
                    for key in user_managed_keys:
                        key_id = key.get('name', '').split('/')[-1]
                        findings.append({
                            "id": f"GCP-IAM-USER-KEY-{sa_email[:8]}",
                            "severity": "Low",
                            "resource": f"Service Account ({sa_email})",
                            "issue": f"Service Account has a User-Managed Key (id: {key_id}). GCP-managed keys are preferred.",
                            "remediation": "Prefer relying on GCP-managed short-lived credentials."
                        })

                        valid_after = key.get('validAfterTime')
                        if valid_after:
                            try:
                                # Parse ISO timestamp e.g. 2023-01-01T00:00:00Z
                                dt = datetime.datetime.fromisoformat(valid_after.replace('Z', '+00:00'))
                                diff_days = (now - dt).days
                                if diff_days > 90:
                                    findings.append({
                                        "id": f"GCP-IAM-KEY-ROTATION-{sa_email[:8]}",
                                        "severity": "High",
                                        "resource": f"SA Key ({sa_email})",
                                        "issue": f"User-managed key is {diff_days} days old. It has not been rotated in the last 90 days.",
                                        "remediation": "Rotate user-managed keys every 90 days."
                                    })
                            except Exception:
                                pass
                except Exception as key_err:
                    print(f"[IAM] Failed to list keys for SA {sa_email}: {key_err}")

        except Exception as sa_err:
            print(f"[IAM] Failed to list service accounts: {sa_err}")

        return {"findings": findings, "scannedCount": scanned_count}

    except Exception as error:
        print(f"[IAM] Critical error during IAM audit: {error}")
        return {"findings": [], "scannedCount": 0, "error": str(error)}
