import json
import concurrent.futures
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from authentication.utils import jwt_required
from projects.models import Project, ScanHistory
from .services.gcp.auth import initialize_gcp_clients
from .services.gcp.auditors.storage_auditor import audit_storage_buckets
from .services.gcp.auditors.vm_auditor import audit_vms
from .services.gcp.auditors.iam_auditor import audit_iam
from .services.gcp.auditors.sql_auditor import audit_cloud_sql
from .services.gcp.auditors.networking_auditor import audit_networking
from .services.gcp.auditors.bigquery_auditor import audit_bigquery
from .services.gcp.auditors.kms_auditor import audit_kms
from .services.gcp.auditors.api_keys_auditor import audit_api_keys
from .services.gcp.auditors.essential_contacts_auditor import audit_essential_contacts
from .services.gcp.auditors.dns_auditor import audit_dns
from .services.gcp.auditors.logging_auditor import audit_logging
from .services.gcp.auditors.dataproc_auditor import audit_dataproc
from .services.gcp.auditors.gke_auditor import audit_gke
from .services.gcp.auditors.serverless_auditor import audit_serverless
from .services.gcp.auditors.lb_auditor import audit_load_balancers
from .services.gcp.auditors.networking_depth_auditor import audit_networking_depth
from .services.aws_scanner import (
    audit_aws_iam,
    audit_aws_ec2,
    audit_aws_s3,
    audit_aws_rds,
    audit_aws_eks,
    audit_aws_lb,
    audit_aws_serverless
)

# Canonical ordering from Major / Big Services to Minor / Auxiliary Services
SERVICE_PRIORITY = {
    # 1. Major Core Services
    "IAM": 1,
    "COMPUTE": 2,
    "VM": 2,
    "EC2": 2,
    "STORAGE": 3,
    "S3": 3,
    "SQL": 4,
    "RDS": 4,
    "NET": 5,
    "FW": 5,
    "FIREWALL": 5,
    "GKE": 6,
    "EKS": 6,
    # 2. Major Platform & Data Services
    "LB": 7,
    "ELB": 7,
    "CLOUDRUN": 8,
    "FUNCTION": 8,
    "SERVERLESS": 8,
    "LAMBDA": 8,
    "BQ": 9,
    "BIGQUERY": 9,
    "KMS": 10,
    "LOG": 11,
    "OBS": 11,
    "MONITOR": 11,
    # 3. Auxiliary / Minor Services
    "DATAPROC": 12,
    "DNS": 13,
    "APIKEY": 14,
    "ESSENTIAL": 15,
}

SEVERITY_PRIORITY = {
    "Critical": 1,
    "High": 2,
    "Medium": 3,
    "Low": 4
}


def sort_findings(findings_list):
    def sort_key(item):
        f_id = item.get("id", "")
        parts = f_id.split("-")
        prefix = parts[1].upper() if len(parts) > 1 else ""
        service_rank = SERVICE_PRIORITY.get(prefix, 99)
        sev_rank = SEVERITY_PRIORITY.get(item.get("severity", "Medium"), 9)
        return (service_rank, sev_rank, f_id)

    return sorted(findings_list, key=sort_key)


GCP_AUDITOR_META = [
    {"name": "IAM", "checks": 8, "fn": lambda c, pid: audit_iam(c["googleAuthClient"], pid)},
    {"name": "VMs", "checks": 10, "fn": lambda c, pid: audit_vms(c["googleAuthClient"], pid)},
    {"name": "Storage", "checks": 4, "fn": lambda c, pid: audit_storage_buckets(c["storageClient"], pid)},
    {"name": "SQL", "checks": 6, "fn": lambda c, pid: audit_cloud_sql(c["googleAuthClient"], pid)},
    {"name": "Networking", "checks": 8, "fn": lambda c, pid: audit_networking(c["googleAuthClient"], pid)},
    {"name": "Kubernetes (GKE)", "checks": 6, "fn": lambda c, pid: audit_gke(c["googleAuthClient"], pid)},
    {"name": "Load Balancers", "checks": 4, "fn": lambda c, pid: audit_load_balancers(c["googleAuthClient"], pid)},
    {"name": "Serverless", "checks": 3, "fn": lambda c, pid: audit_serverless(c["googleAuthClient"], pid)},
    {"name": "BigQuery", "checks": 3, "fn": lambda c, pid: audit_bigquery(c["bigQueryClient"], pid)},
    {"name": "KMS", "checks": 3, "fn": lambda c, pid: audit_kms(c["googleAuthClient"], pid)},
    {"name": "Logging", "checks": 12, "fn": lambda c, pid: audit_logging(c["googleAuthClient"], pid)},
    {"name": "Dataproc", "checks": 2, "fn": lambda c, pid: audit_dataproc(c["googleAuthClient"], pid)},
    {"name": "DNS", "checks": 2, "fn": lambda c, pid: audit_dns(c["googleAuthClient"], pid)},
    {"name": "API Keys", "checks": 2, "fn": lambda c, pid: audit_api_keys(c["googleAuthClient"], pid)},
    {"name": "Essential Contacts", "checks": 1, "fn": lambda c, pid: audit_essential_contacts(c["googleAuthClient"], pid)},
    {"name": "Deep Networking", "checks": 1, "fn": lambda c, pid: audit_networking_depth(c["googleAuthClient"], pid)},
]


@csrf_exempt
@jwt_required
def scan_gcp_view(request):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    print("--- Received COMPREHENSIVE LIVE GCP Scan Request ---")
    user = request.user_obj
    credentials = None

    try:
        if "file" in request.FILES:
            file_content = request.FILES["file"].read().decode("utf-8")
            credentials = json.loads(file_content)
        elif request.POST.get("credentials"):
            credentials = json.loads(request.POST.get("credentials"))
        elif request.content_type == "application/json" and request.body:
            body = json.loads(request.body.decode("utf-8") or "{}")
            raw_creds = body.get("credentials")
            if isinstance(raw_creds, str):
                credentials = json.loads(raw_creds)
            elif isinstance(raw_creds, dict):
                credentials = raw_creds
        else:
            return JsonResponse({"error": "Missing GCP credentials (file or JSON body required)."}, status=400)

        if not credentials:
            return JsonResponse({"error": "Missing GCP credentials (file or JSON body required)."}, status=400)

        clients = initialize_gcp_clients(credentials)
        gcp_project_id = clients["projectId"]

        print(f"[Engine] Beginning comprehensive audit for Project: {gcp_project_id} across 16 security modules...")

        raw_findings = []
        total_scanned = 0
        skipped_checks = []
        total_checkpoints = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            future_to_meta = {
                executor.submit(meta["fn"], clients, gcp_project_id): meta
                for meta in GCP_AUDITOR_META
            }
            for future in concurrent.futures.as_completed(future_to_meta):
                meta = future_to_meta[future]
                mod_name = meta["name"]
                checks_count = meta["checks"]
                try:
                    res = future.result()
                    if res:
                        findings = res.get("findings", [])
                        count = res.get("scannedCount", 0)
                        raw_findings.extend(findings)
                        total_scanned += count

                        service_validations = max(1, count * checks_count)
                        total_checkpoints += service_validations

                        if res.get("skipped") or res.get("error"):
                            skipped_checks.append({
                                "service": mod_name,
                                "reason": res.get("reason") or res.get("error") or "API not enabled"
                            })
                except Exception as exc:
                    print(f"[Engine] Auditor {mod_name} encountered an error: {exc}")
                    skipped_checks.append({
                        "service": mod_name,
                        "reason": str(exc)
                    })

        # Sort findings deterministically from Big Services to Minor Services, then by Severity
        all_findings = sort_findings(raw_findings)

        critical_count = len([f for f in all_findings if f.get("severity") == "Critical"])
        high_count = len([f for f in all_findings if f.get("severity") == "High"])
        medium_count = len([f for f in all_findings if f.get("severity") == "Medium"])
        low_count = len([f for f in all_findings if f.get("severity") == "Low"])

        unique_vulnerable_resources = len(set(f.get("resource") for f in all_findings if f.get("resource")))

        computed_score = 100
        if total_scanned > 0:
            computed_score = round(((total_scanned - unique_vulnerable_resources) / total_scanned) * 100)
            computed_score = max(0, computed_score)

        total_checks_val = max(77, total_checkpoints)

        # Database Persistence
        project_name = gcp_project_id or "GCP Project"
        project = Project.objects.filter(name=project_name, user=user, provider="gcp").first()
        creds_json = json.dumps(credentials)

        if not project:
            project = Project.objects.create(
                name=project_name,
                provider="gcp",
                user=user,
                credentials=creds_json
            )
        else:
            project.credentials = creds_json
            project.save()

        scan_record = ScanHistory.objects.create(
            score=computed_score,
            scannedResources=total_scanned,
            totalChecks=total_checks_val,
            skippedChecks=json.dumps(skipped_checks),
            criticalCount=critical_count,
            highCount=high_count,
            mediumCount=medium_count,
            findings=json.dumps(all_findings),
            project=project
        )

        live_results = {
            "success": True,
            "projectId": gcp_project_id,
            "dbScanId": scan_record.id,
            "dbProjectId": scan_record.project_id,
            "totalChecks": total_checks_val,
            "skippedChecks": skipped_checks,
            "summary": {
                "score": computed_score,
                "scannedResources": total_scanned,
                "totalChecks": total_checks_val,
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count
            },
            "vulnerabilities": all_findings
        }

        print(f"[Engine] Scan complete. Total Scanned: {total_scanned}, Vulnerabilities: {len(all_findings)}, Score: {computed_score}% (Scan ID: {scan_record.id}).")
        return JsonResponse(live_results, status=200)

    except Exception as error:
        print(f"[Engine] Scanner crashed: {error}")
        return JsonResponse({"error": str(error) or "Internal server error during GCP scan."}, status=500)


@csrf_exempt
@jwt_required
def scan_aws_view(request):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    print("--- Received COMPREHENSIVE LIVE AWS Scan Request ---")
    user = request.user_obj

    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
        access_key_id = body.get("accessKeyId", "").strip()
        secret_access_key = body.get("secretAccessKey", "").strip()
        region = body.get("region", "us-east-1").strip() or "us-east-1"

        if not access_key_id or not secret_access_key:
            return JsonResponse({"error": "Missing AWS credentials (accessKeyId, secretAccessKey required)."}, status=400)

        credentials = {
            "accessKeyId": access_key_id,
            "secretAccessKey": secret_access_key,
            "region": region
        }
        masked_key_id = access_key_id[:4] + "..."
        print(f"[Engine] Beginning comprehensive AWS audit for Access Key: {masked_key_id}")

        tasks = [
            ("IAM", lambda: audit_aws_iam(credentials)),
            ("EC2", lambda: audit_aws_ec2(credentials)),
            ("S3", lambda: audit_aws_s3(credentials)),
            ("RDS", lambda: audit_aws_rds(credentials)),
            ("EKS", lambda: audit_aws_eks(credentials)),
            ("Load Balancers", lambda: audit_aws_lb(credentials)),
            ("Serverless", lambda: audit_aws_serverless(credentials)),
        ]

        raw_findings = []
        total_scanned = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=7) as executor:
            future_to_name = {executor.submit(task[1]): task[0] for task in tasks}
            for future in concurrent.futures.as_completed(future_to_name):
                mod_name = future_to_name[future]
                try:
                    res = future.result()
                    if res:
                        findings = res.get("findings", [])
                        count = res.get("scannedCount", 0)
                        raw_findings.extend(findings)
                        total_scanned += count
                except Exception as exc:
                    print(f"[Engine] AWS Auditor {mod_name} failed: {exc}")

        # Sort findings by Big Service to Minor, and Critical to Low
        all_findings = sort_findings(raw_findings)

        critical_count = len([f for f in all_findings if f.get("severity") == "Critical"])
        high_count = len([f for f in all_findings if f.get("severity") == "High"])
        medium_count = len([f for f in all_findings if f.get("severity") == "Medium"])
        low_count = len([f for f in all_findings if f.get("severity") == "Low"])

        unique_vulnerable_resources = len(set(f.get("resource") for f in all_findings if f.get("resource")))

        computed_score = 100
        if total_scanned > 0:
            computed_score = round(((total_scanned - unique_vulnerable_resources) / total_scanned) * 100)
            computed_score = max(0, computed_score)

        project_name = f"AWS Project ({masked_key_id})"
        project = Project.objects.filter(name=project_name, user=user, provider="aws").first()
        creds_json = json.dumps(credentials)

        if not project:
            project = Project.objects.create(
                name=project_name,
                provider="aws",
                user=user,
                credentials=creds_json
            )
        else:
            project.credentials = creds_json
            project.save()

        scan_record = ScanHistory.objects.create(
            score=computed_score,
            scannedResources=total_scanned,
            totalChecks=35,
            criticalCount=critical_count,
            highCount=high_count,
            mediumCount=medium_count,
            findings=json.dumps(all_findings),
            project=project
        )

        live_results = {
            "success": True,
            "projectId": project_name,
            "dbScanId": scan_record.id,
            "dbProjectId": scan_record.project_id,
            "provider": "AWS",
            "summary": {
                "score": computed_score,
                "scannedResources": total_scanned,
                "vulnerableCount": unique_vulnerable_resources,
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count
            },
            "vulnerabilities": all_findings
        }

        return JsonResponse(live_results, status=200)

    except Exception as error:
        print(f"[Engine] AWS Scanner crashed: {error}")
        return JsonResponse({"error": str(error) or "Internal server error during AWS scan."}, status=500)
