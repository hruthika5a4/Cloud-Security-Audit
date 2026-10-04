import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from django.test import Client
from authentication.models import User
from projects.models import Project, ScanHistory

client = Client()

print("--- 1. Testing Health Check ---")
res = client.get('/api/health')
print("Health status:", res.status_code, res.json())
assert res.status_code == 200
assert res.json()['status'] == 'ok'

print("\n--- 2. Testing User Registration ---")
test_email = "tester@auditscope.io"
User.objects.filter(email=test_email).delete()

reg_res = client.post(
    '/api/auth/register',
    data=json.dumps({"email": test_email, "password": "Password123!", "name": "Security Auditor"}),
    content_type='application/json'
)
print("Register status:", reg_res.status_code, reg_res.json())
assert reg_res.status_code == 201

user = User.objects.get(email=test_email)
otp = user.otp
print("Generated OTP:", otp)

print("\n--- 3. Testing Verify OTP ---")
ver_res = client.post(
    '/api/auth/verify-otp',
    data=json.dumps({"email": test_email, "otp": otp}),
    content_type='application/json'
)
print("Verify OTP status:", ver_res.status_code, ver_res.json())
assert ver_res.status_code == 200
token = ver_res.json()['token']
auth_headers = {'HTTP_AUTHORIZATION': f'Bearer {token}'}

print("\n--- 4. Testing Login ---")
login_res = client.post(
    '/api/auth/login',
    data=json.dumps({"email": test_email, "password": "Password123!"}),
    content_type='application/json'
)
print("Login status:", login_res.status_code, login_res.json())
assert login_res.status_code == 200

print("\n--- 5. Testing /api/auth/me ---")
me_res = client.get('/api/auth/me', **auth_headers)
print("Me status:", me_res.status_code, me_res.json())
assert me_res.status_code == 200
assert me_res.json()['email'] == test_email

print("\n--- 6. Testing Project Creation & Listing ---")
proj_res = client.post(
    '/api/projects',
    data=json.dumps({"name": "Production GCP Infrastructure", "provider": "gcp"}),
    content_type='application/json',
    **auth_headers
)
print("Create Project status:", proj_res.status_code, proj_res.json())
assert proj_res.status_code == 201
project_id = proj_res.json()['id']

list_res = client.get('/api/projects', **auth_headers)
print("List Projects status:", list_res.status_code, len(list_res.json()))
assert list_res.status_code == 200

print("\n--- 7. Testing Scan History Persistence & Retrieval ---")
scan = ScanHistory.objects.create(
    score=92,
    scannedResources=24,
    criticalCount=0,
    highCount=1,
    mediumCount=2,
    findings=json.dumps([
        {
            "id": "GCP-STORAGE-PAP-bucket123",
            "severity": "High",
            "resource": "Storage Bucket (prod-data)",
            "issue": "Public Access Prevention is NOT enforced.",
            "remediation": "Enforce Public Access Prevention."
        }
    ]),
    project_id=project_id
)
scans_res = client.get(f'/api/projects/{project_id}/scans', **auth_headers)
print("Project Scans status:", scans_res.status_code, len(scans_res.json()))
assert scans_res.status_code == 200
assert isinstance(scans_res.json()[0]['findings'], list)

print("\n--- 8. Testing Excel & PDF Generation Endpoints ---")
excel_res = client.post(
    '/api/reports/export-excel',
    data=json.dumps({
        "projectName": "Production GCP Infrastructure",
        "scanData": {
            "score": 92,
            "scannedResources": 24,
            "criticalCount": 0,
            "highCount": 1,
            "mediumCount": 2,
            "findings": [
                {
                    "id": "GCP-STORAGE-PAP-bucket123",
                    "severity": "High",
                    "resource": "Storage Bucket (prod-data)",
                    "issue": "Public Access Prevention is NOT enforced.",
                    "remediation": "Enforce Public Access Prevention."
                }
            ]
        }
    }),
    content_type='application/json',
    **auth_headers
)
print("Excel export status:", excel_res.status_code, "Length:", len(excel_res.content))
assert excel_res.status_code == 200
assert len(excel_res.content) > 1000

pdf_res = client.post(
    '/api/reports/download',
    data=json.dumps({
        "projectId": "Production GCP Infrastructure",
        "scanData": {
            "score": 92,
            "scannedResources": 24,
            "criticalCount": 0,
            "highCount": 1,
            "mediumCount": 2,
            "vulnerabilities": [
                {
                    "id": "GCP-STORAGE-PAP-bucket123",
                    "severity": "High",
                    "resource": "Storage Bucket (prod-data)",
                    "issue": "Public Access Prevention is NOT enforced.",
                    "remediation": "Enforce Public Access Prevention."
                }
            ]
        }
    }),
    content_type='application/json',
    **auth_headers
)
print("PDF download status:", pdf_res.status_code, "Length:", len(pdf_res.content))
assert pdf_res.status_code == 200
assert len(pdf_res.content) > 1000

print("\n--- 9. Testing Schedule Automation Endpoints ---")
sched_res = client.post(
    '/api/schedules',
    data=json.dumps({
        "projectId": project_id,
        "frequency": "daily",
        "time": "09:00",
        "daysOfWeek": ["Monday", "Wednesday"],
        "targetEmail": "admin@auditscope.io"
    }),
    content_type='application/json',
    **auth_headers
)
print("Schedule creation status:", sched_res.status_code, sched_res.json())
assert sched_res.status_code == 201
schedule_id = sched_res.json()['id']

sched_list_res = client.get('/api/schedules', **auth_headers)
print("Schedule list status:", sched_list_res.status_code, len(sched_list_res.json()))
assert sched_list_res.status_code == 200

toggle_res = client.patch(f'/api/schedules/{schedule_id}/toggle', **auth_headers)
print("Toggle schedule status:", toggle_res.status_code, toggle_res.json()['isActive'])
assert toggle_res.status_code == 200

print("\n=============================================")
print("ALL INTEGRATION TESTS PASSED WITH 100% SUCCESS!")
print("=============================================")
