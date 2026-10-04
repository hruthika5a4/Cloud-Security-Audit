import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, JsonResponse
from authentication.utils import jwt_required
from projects.models import Project, ScanHistory
from .services.pdf_generator import generate_pdf_report
from .services.excel_generator import generate_excel_report, get_category_from_id


@csrf_exempt
@jwt_required
def export_excel_view(request):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        user = request.user_obj
        data = json.loads(request.body.decode("utf-8") or "{}")

        scan_id = data.get("scanId")
        scan_data = data.get("scanData")

        scan_dict = {}
        project_name = "Security Audit"

        if scan_id:
            scan_record = ScanHistory.objects.filter(id=scan_id).select_related("project").first()
            if not scan_record:
                return JsonResponse({"error": "Scan record not found in database."}, status=404)
            scan_dict = scan_record.to_dict(include_project=True, parse_findings=True)
            if scan_record.project:
                project_name = scan_record.project.name
        elif scan_data:
            scan_dict = scan_data
            project_name = scan_data.get("projectName") or scan_data.get("projectId") or scan_data.get("provider") or "Security Audit"
        else:
            return JsonResponse({"error": "Either scanId or scanData is required."}, status=400)

        excel_bytes = generate_excel_report(scan_dict, project_name)

        response = HttpResponse(
            excel_bytes,
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
        clean_name = str(project_name).replace(" ", "_")
        response["Content-Disposition"] = f'attachment; filename="Security_Audit_{clean_name}.xlsx"'
        response["Content-Length"] = len(excel_bytes)
        return response

    except Exception as e:
        print(f"[Report] export-excel error: {e}")
        return JsonResponse({"error": f"Failed to generate Excel report: {str(e)}"}, status=500)


@csrf_exempt
@jwt_required
def download_pdf_view(request):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        user = request.user_obj
        data = json.loads(request.body.decode("utf-8") or "{}")

        scan_id = data.get("scanId")
        scan_data = data.get("scanData") or data
        selected_services = data.get("selectedServices")

        scan_dict = {}
        project_id = "Cloud Project"

        if scan_id:
            scan_record = ScanHistory.objects.filter(id=scan_id).select_related("project").first()
            if not scan_record:
                return JsonResponse({"error": "Scan record not found."}, status=404)
            scan_dict = scan_record.to_dict(include_project=True, parse_findings=True)
            if scan_record.project:
                project_id = scan_record.project.name
        else:
            scan_dict = scan_data
            project_id = data.get("projectId") or scan_data.get("projectId") or scan_data.get("provider", "").upper() or "Cloud Project"

        # Apply selected services filtering if specified
        if selected_services and "ALL" not in selected_services:
            vulns = scan_dict.get("vulnerabilities") or scan_dict.get("findings") or []
            filtered_vulns = [v for v in vulns if get_category_from_id(v.get("id", "")) in selected_services]
            scan_dict["vulnerabilities"] = filtered_vulns
            scan_dict["findings"] = filtered_vulns

        pdf_bytes = generate_pdf_report(scan_dict, user.name or user.email, project_id)

        response = HttpResponse(pdf_bytes, content_type="application/pdf")
        clean_name = str(project_id).replace(" ", "_")
        response["Content-Disposition"] = f'attachment; filename="AuditScope_Report_{clean_name}.pdf"'
        response["Content-Length"] = len(pdf_bytes)
        return response

    except Exception as e:
        print(f"[Report] PDF Download Error: {e}")
        return JsonResponse({"error": f"Failed to generate report: {str(e)}"}, status=500)


@csrf_exempt
@jwt_required
def send_email_view(request):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        user = request.user_obj
        data = json.loads(request.body.decode("utf-8") or "{}")

        scan_data = data.get("scanData")
        recipient_email = data.get("recipientEmail") or data.get("email") or user.email
        selected_services = data.get("selectedServices")
        send_pdf = data.get("sendPdf", True)
        send_excel = data.get("sendExcel", False)

        if not scan_data:
            scan_id = data.get("scanId")
            if scan_id:
                scan_record = ScanHistory.objects.filter(id=scan_id).select_related("project").first()
                if scan_record:
                    scan_data = scan_record.to_dict(include_project=True, parse_findings=True)
            if not scan_data:
                return JsonResponse({"error": "scanData is required in the request body."}, status=400)

        if selected_services and "ALL" not in selected_services:
            vulns = scan_data.get("vulnerabilities") or scan_data.get("findings") or []
            filtered_vulns = [v for v in vulns if get_category_from_id(v.get("id", "")) in selected_services]
            scan_data["vulnerabilities"] = filtered_vulns
            scan_data["findings"] = filtered_vulns

        project_id = scan_data.get("projectId") or scan_data.get("provider", "").upper() or "Cloud Project"
        email_attachments = []

        if send_pdf:
            pdf_bytes = generate_pdf_report(scan_data, user.name or user.email, project_id)
            clean_name = str(project_id).replace(" ", "_")
            email_attachments.append({
                "filename": f"AuditScope_Report_{clean_name}.pdf",
                "content": pdf_bytes,
                "subtype": "pdf"
            })

        if send_excel:
            excel_bytes = generate_excel_report(scan_data, project_id)
            clean_name = str(project_id).replace(" ", "_")
            email_attachments.append({
                "filename": f"Security_Audit_{clean_name}.xlsx",
                "content": excel_bytes,
                "subtype": "vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            })

        if not email_attachments:
            return JsonResponse({"error": "No report formats selected."}, status=400)

        if not settings.SMTP_USER or settings.SMTP_USER == 'your-email@gmail.com' or not settings.SMTP_PASS:
            print("--- DEVELOPMENT MODE: SMTP NOT CONFIGURED ---")
            print(f"Simulating Report Email to {recipient_email} with {len(email_attachments)} attachments")
            print("---------------------------------------------")
            return JsonResponse({"success": True, "message": f"Report emailed to {recipient_email} (Simulated - SMTP not configured)"})

        msg = MIMEMultipart()
        msg["Subject"] = f"Confidential Security Audit Report — {project_id}"
        msg["From"] = f'"AuditScope Security" <{settings.SMTP_USER}>'
        msg["To"] = recipient_email

        html_body = f"""
        <div style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; max-width: 650px; margin: 0 auto; padding: 30px; border: 1px solid #e2e8f0; border-radius: 8px; color: #334155;">
          <h2 style="color: #0f172a; border-bottom: 2px solid #06b6d4; padding-bottom: 10px; margin-bottom: 20px;">Confidential Security Audit Report</h2>
          <p style="font-size: 16px; line-height: 1.6;">Dear Stakeholder,</p>
          <p style="font-size: 16px; line-height: 1.6;">Please find the attached comprehensive security audit report detailing the vulnerability posture and infrastructure analysis for the project: <strong style="color: #0f172a;">${project_id}</strong>.</p>
          <table style="width: 100%; margin: 25px 0; border-collapse: collapse;">
            <tbody>
              <tr>
                <td style="padding: 12px; border: 1px solid #e2e8f0; font-weight: bold; width: 40%; background-color: #f8fafc;">Aggregate Safety Score</td>
                <td style="padding: 12px; border: 1px solid #e2e8f0; font-weight: bold; color: {'#16a34a' if scan_data.get('score', 0) > 80 else '#dc2626'};">{scan_data.get('score', 0)}%</td>
              </tr>
              <tr>
                <td style="padding: 12px; border: 1px solid #e2e8f0; font-weight: bold; background-color: #f8fafc;">Total Vulnerabilities Identified</td>
                <td style="padding: 12px; border: 1px solid #e2e8f0;">{len(scan_data.get('vulnerabilities') or scan_data.get('findings') or [])}</td>
              </tr>
              <tr>
                <td style="padding: 12px; border: 1px solid #e2e8f0; font-weight: bold; background-color: #f8fafc;">Total Infrastructure Entities Scanned</td>
                <td style="padding: 12px; border: 1px solid #e2e8f0;">{scan_data.get('scannedResources') or scan_data.get('scanned', 0)}</td>
              </tr>
            </tbody>
          </table>
        </div>
        """
        msg.attach(MIMEText(html_body, "html"))

        for att in email_attachments:
            part = MIMEApplication(att["content"], _subtype=att["subtype"])
            part.add_header("Content-Disposition", "attachment", filename=att["filename"])
            msg.attach(part)

        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASS)
            server.sendmail(settings.SMTP_USER, [recipient_email], msg.as_string())

        return JsonResponse({"success": True, "message": f"Report sent to {recipient_email}"})

    except Exception as e:
        print(f"[Report] Send Email Error: {e}")
        return JsonResponse({"error": f"Failed to send email: {str(e)}"}, status=500)


@csrf_exempt
@jwt_required
def project_summary_view(request):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        user = request.user_obj
        data = json.loads(request.body.decode("utf-8") or "{}")
        project_id = data.get("projectId")

        project = Project.objects.filter(id=project_id, user=user).first()
        if not project:
            return JsonResponse({"error": "Project not found."}, status=404)

        latest_scan = ScanHistory.objects.filter(project=project).order_by("-createdAt").first()
        if not latest_scan:
            return JsonResponse({"error": "No scan records found for this project."}, status=404)

        scan_dict = latest_scan.to_dict(parse_findings=True)
        pdf_bytes = generate_pdf_report(scan_dict, user.name or user.email, project.name)

        response = HttpResponse(pdf_bytes, content_type="application/pdf")
        clean_name = str(project.name).replace(" ", "_")
        response["Content-Disposition"] = f'attachment; filename="Project_Summary_{clean_name}.pdf"'
        response["Content-Length"] = len(pdf_bytes)
        return response

    except Exception as e:
        print(f"[Report] Project Summary Error: {e}")
        return JsonResponse({"error": "Failed to generate project summary."}, status=500)
