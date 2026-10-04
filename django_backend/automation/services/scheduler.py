import json
import smtplib
import datetime
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from django.conf import settings
from django.utils import timezone
from authentication.models import User
from projects.models import Project, ScanHistory
from scanner.services.gcp.auth import initialize_gcp_clients
from scanner.services.gcp.auditors.storage_auditor import audit_storage_buckets
from scanner.services.gcp.auditors.vm_auditor import audit_vms
from scanner.services.gcp.auditors.iam_auditor import audit_iam
from scanner.services.gcp.auditors.sql_auditor import audit_cloud_sql
from scanner.services.gcp.auditors.networking_auditor import audit_networking
from scanner.services.gcp.auditors.bigquery_auditor import audit_bigquery
from scanner.services.gcp.auditors.kms_auditor import audit_kms
from scanner.services.gcp.auditors.api_keys_auditor import audit_api_keys
from scanner.services.gcp.auditors.essential_contacts_auditor import audit_essential_contacts
from scanner.services.gcp.auditors.dns_auditor import audit_dns
from scanner.services.gcp.auditors.logging_auditor import audit_logging
from scanner.services.gcp.auditors.dataproc_auditor import audit_dataproc
from scanner.services.gcp.auditors.gke_auditor import audit_gke
from scanner.services.gcp.auditors.serverless_auditor import audit_serverless
from scanner.services.gcp.auditors.lb_auditor import audit_load_balancers
from scanner.services.gcp.auditors.networking_depth_auditor import audit_networking_depth
from scanner.services.aws_scanner import audit_aws_iam, audit_aws_ec2, audit_aws_s3
from reports.services.pdf_generator import generate_pdf_report
from reports.services.excel_generator import generate_excel_report


def compute_next_run(frequency, time_str, days_of_week=None, day_of_month=None, tz_offset=0):
    now = timezone.now()
    # local now
    local_now = now - datetime.timedelta(minutes=tz_offset)
    hours, minutes = map(int, time_str.split(':'))

    next_local = datetime.datetime(
        local_now.year, local_now.month, local_now.day,
        hours, minutes, 0, tzinfo=datetime.timezone.utc
    )

    if next_local <= local_now:
        if frequency == 'daily':
            next_local += datetime.timedelta(days=1)
        elif frequency == 'weekly':
            next_local += datetime.timedelta(days=1)
        elif frequency == 'monthly':
            # Add one month
            next_month = (local_now.month % 12) + 1
            next_year = local_now.year + (1 if local_now.month == 12 else 0)
            next_local = datetime.datetime(next_year, next_month, local_now.day, hours, minutes, 0, tzinfo=datetime.timezone.utc)

    if frequency == 'weekly' and days_of_week:
        day_map = {'Sunday': 6, 'Monday': 0, 'Tuesday': 1, 'Wednesday': 2, 'Thursday': 3, 'Friday': 4, 'Saturday': 5}
        day_indices = [day_map[d] for d in days_of_week if d in day_map]
        for i in range(8):
            check_date = datetime.datetime(
                local_now.year, local_now.month, local_now.day,
                hours, minutes, 0, tzinfo=datetime.timezone.utc
            ) + datetime.timedelta(days=i)
            if check_date > local_now and check_date.weekday() in day_indices:
                next_local = check_date
                break

    if frequency == 'monthly' and day_of_month:
        try:
            next_month_dt = datetime.datetime(
                local_now.year, local_now.month, day_of_month,
                hours, minutes, 0, tzinfo=datetime.timezone.utc
            )
            if next_month_dt <= local_now:
                next_m = (local_now.month % 12) + 1
                next_y = local_now.year + (1 if local_now.month == 12 else 0)
                next_month_dt = datetime.datetime(
                    next_y, next_m, day_of_month,
                    hours, minutes, 0, tzinfo=datetime.timezone.utc
                )
            next_local = next_month_dt
        except Exception:
            pass

    return next_local + datetime.timedelta(minutes=tz_offset)


def ensure_project_linked(schedule, credentials_source):
    if schedule.project_id:
        return schedule.project_id

    print(f"[Scheduler] No projectId on schedule {schedule.id}, creating a project record...")
    try:
        project_name = 'Automated Scan'
        provider = schedule.project.provider if schedule.project else 'gcp'

        if provider == 'gcp' and credentials_source:
            try:
                parsed = json.loads(credentials_source) if isinstance(credentials_source, str) else credentials_source
                if parsed.get("project_id"):
                    project_name = parsed["project_id"]
            except Exception:
                pass
        elif provider == 'aws' and credentials_source:
            try:
                parsed = json.loads(credentials_source) if isinstance(credentials_source, str) else credentials_source
                if parsed.get("accessKeyId"):
                    project_name = f"AWS Project ({parsed['accessKeyId'][:6]}...)"
            except Exception:
                pass

        new_project = Project.objects.create(
            name=project_name,
            provider=provider,
            credentials=credentials_source if isinstance(credentials_source, str) else json.dumps(credentials_source),
            user=schedule.user
        )

        schedule.project = new_project
        schedule.save()
        return new_project.id
    except Exception as err:
        print(f"[Scheduler] Failed to create project record: {err}")
        return None


def send_audit_email(user_email, scan_data, project_name):
    print(f"[Scheduler] 📧 Preparing to send audit report to: {user_email}")
    if not settings.SMTP_USER or settings.SMTP_USER == 'your-email@gmail.com' or not settings.SMTP_PASS:
        print("--- DEV MODE: SMTP Not Configured for Scheduler Email ---")
        return

    try:
        pdf_scan_data = {
            "score": scan_data.score if hasattr(scan_data, "score") else scan_data.get("score"),
            "vulnerabilities": json.loads(scan_data.findings) if isinstance(getattr(scan_data, "findings", None), str) else (getattr(scan_data, "findings", []) or scan_data.get("vulnerabilities", [])),
            "scanned": scan_data.scannedResources if hasattr(scan_data, "scannedResources") else scan_data.get("scannedResources", 0)
        }
        pdf_bytes = generate_pdf_report(pdf_scan_data, user_email, project_name)
        excel_bytes = generate_excel_report(pdf_scan_data, project_name)

        msg = MIMEMultipart()
        msg["Subject"] = f"[Automated] Security Audit: {project_name} — Score {pdf_scan_data['score']}%"
        msg["From"] = f'"AuditScope Automation" <{settings.SMTP_USER}>'
        msg["To"] = user_email

        html = f"""
        <div style="font-family: sans-serif; color: #333; line-height: 1.6;">
            <h2 style="color: #4f46e5;">Cloud Security Audit Report</h2>
            <p>Hello,</p>
            <p>The automated security audit for project <strong>{project_name}</strong> has been completed.</p>
            <div style="margin: 20px 0; padding: 15px; background: #f8fafc; border-radius: 8px; border-left: 4px solid #4f46e5;">
                <p style="margin: 0;"><strong>Security Score:</strong> {pdf_scan_data['score']}%</p>
                <p style="margin: 5px 0 0 0;"><strong>Findings:</strong> {getattr(scan_data, 'criticalCount', 0)} Critical, {getattr(scan_data, 'highCount', 0)} High</p>
            </div>
            <p>Please find the detailed PDF and Excel reports attached to this email.</p>
        </div>
        """
        msg.attach(MIMEText(html, "html"))

        clean_name = str(project_name).replace(" ", "_")
        pdf_part = MIMEApplication(pdf_bytes, _subtype="pdf")
        pdf_part.add_header("Content-Disposition", "attachment", filename=f"Security_Audit_{clean_name}.pdf")
        msg.attach(pdf_part)

        excel_part = MIMEApplication(excel_bytes, _subtype="vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        excel_part.add_header("Content-Disposition", "attachment", filename=f"Security_Audit_{clean_name}.xlsx")
        msg.attach(excel_part)

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASS)
            server.sendmail(settings.SMTP_USER, [user_email], msg.as_string())

        print(f"[Scheduler] ✅ Email successfully delivered to {user_email}")
    except Exception as err:
        print(f"[Scheduler] ❌ sendAuditEmail failed: {err}")


def run_gcp_scan(credentials, project_id):
    try:
        creds = json.loads(credentials) if isinstance(credentials, str) else credentials
        clients = initialize_gcp_clients(creds)
        gcp_project_id = clients["projectId"]

        auditors = [
            lambda: audit_storage_buckets(clients["storageClient"], gcp_project_id),
            lambda: audit_vms(clients["googleAuthClient"], gcp_project_id),
            lambda: audit_iam(clients["googleAuthClient"], gcp_project_id),
            lambda: audit_cloud_sql(clients["googleAuthClient"], gcp_project_id),
            lambda: audit_networking(clients["googleAuthClient"], gcp_project_id),
            lambda: audit_bigquery(clients["bigQueryClient"], gcp_project_id),
            lambda: audit_kms(clients["googleAuthClient"], gcp_project_id),
            lambda: audit_api_keys(clients["googleAuthClient"], gcp_project_id),
            lambda: audit_essential_contacts(clients["googleAuthClient"], gcp_project_id),
            lambda: audit_dns(clients["googleAuthClient"], gcp_project_id),
            lambda: audit_logging(clients["googleAuthClient"], gcp_project_id),
            lambda: audit_dataproc(clients["googleAuthClient"], gcp_project_id),
            lambda: audit_gke(clients["googleAuthClient"], gcp_project_id),
            lambda: audit_load_balancers(clients["googleAuthClient"], gcp_project_id),
            lambda: audit_serverless(clients["googleAuthClient"], gcp_project_id),
            lambda: audit_networking_depth(clients["googleAuthClient"], gcp_project_id),
        ]

        all_findings = []
        total_scanned = 0

        for fn in auditors:
            try:
                res = fn()
                if res:
                    all_findings.extend(res.get("findings", []))
                    total_scanned += res.get("scannedCount", 0)
            except Exception as e:
                print(f"[Scheduler GCP Scan] Auditor exception: {e}")

        critical_count = len([f for f in all_findings if f.get("severity") == "Critical"])
        high_count = len([f for f in all_findings if f.get("severity") == "High"])
        medium_count = len([f for f in all_findings if f.get("severity") == "Medium"])

        unique_vulnerable = len(set(f.get("resource") for f in all_findings if f.get("resource")))
        computed_score = 100
        if total_scanned > 0:
            computed_score = max(0, round(((total_scanned - unique_vulnerable) / total_scanned) * 100))

        if project_id:
            project = Project.objects.filter(id=project_id).first()
            if project:
                saved = ScanHistory.objects.create(
                    score=computed_score,
                    scannedResources=total_scanned,
                    criticalCount=critical_count,
                    highCount=high_count,
                    mediumCount=medium_count,
                    findings=json.dumps(all_findings),
                    project=project
                )
                return saved

        return {
            "score": computed_score,
            "scannedResources": total_scanned,
            "criticalCount": critical_count,
            "highCount": high_count,
            "mediumCount": medium_count,
            "findings": json.dumps(all_findings)
        }
    except Exception as err:
        print(f"[Scheduler] GCP scan failed for project {project_id}: {err}")
        return None


def run_aws_scan(credentials, project_id):
    try:
        creds = json.loads(credentials) if isinstance(credentials, str) else credentials
        auditors = [
            lambda: audit_aws_iam(creds),
            lambda: audit_aws_ec2(creds),
            lambda: audit_aws_s3(creds)
        ]

        all_findings = []
        total_scanned = 0

        for fn in auditors:
            try:
                res = fn()
                if res:
                    all_findings.extend(res.get("findings", []))
                    total_scanned += res.get("scannedCount", 0)
            except Exception as e:
                print(f"[Scheduler AWS Scan] Auditor exception: {e}")

        critical_count = len([f for f in all_findings if f.get("severity") == "Critical"])
        high_count = len([f for f in all_findings if f.get("severity") == "High"])
        medium_count = len([f for f in all_findings if f.get("severity") == "Medium"])

        unique_vulnerable = len(set(f.get("resource") for f in all_findings if f.get("resource")))
        computed_score = 100
        if total_scanned > 0:
            computed_score = max(0, round(((total_scanned - unique_vulnerable) / total_scanned) * 100))

        if project_id:
            project = Project.objects.filter(id=project_id).first()
            if project:
                saved = ScanHistory.objects.create(
                    score=computed_score,
                    scannedResources=total_scanned,
                    criticalCount=critical_count,
                    highCount=high_count,
                    mediumCount=medium_count,
                    findings=json.dumps(all_findings),
                    project=project
                )
                return saved

        return {
            "score": computed_score,
            "scannedResources": total_scanned,
            "criticalCount": critical_count,
            "highCount": high_count,
            "mediumCount": medium_count,
            "findings": json.dumps(all_findings)
        }
    except Exception as err:
        print(f"[Scheduler] AWS scan failed for project {project_id}: {err}")
        return None
