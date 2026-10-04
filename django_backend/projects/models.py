import uuid
import json
from django.db import models
from django.utils import timezone
from authentication.models import User, generate_object_id


class Project(models.Model):
    id = models.CharField(primary_key=True, max_length=64, default=generate_object_id, editable=False)
    name = models.CharField(max_length=255)
    provider = models.CharField(max_length=50)  # e.g. 'gcp', 'aws'
    credentials = models.TextField(null=True, blank=True)
    createdAt = models.DateTimeField(default=timezone.now)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="projects", db_column="userId")

    def to_dict(self, include_scans_count=False):
        data = {
            "id": self.id,
            "name": self.name,
            "provider": self.provider,
            "credentials": self.credentials,
            "createdAt": self.createdAt.isoformat() if self.createdAt else None,
            "userId": self.user_id,
        }
        if include_scans_count:
            data["_count"] = {"scans": self.scans.count()}
        return data

    def __str__(self):
        return f"{self.name} ({self.provider})"


SERVICE_PRIORITY = {
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


def sort_findings_list(findings_list):
    if not isinstance(findings_list, list):
        return findings_list

    def sort_key(item):
        if not isinstance(item, dict):
            return (99, 9, "")
        f_id = item.get("id", "")
        parts = f_id.split("-")
        prefix = parts[1].upper() if len(parts) > 1 else ""
        service_rank = SERVICE_PRIORITY.get(prefix, 99)
        sev_rank = SEVERITY_PRIORITY.get(item.get("severity", "Medium"), 9)
        return (service_rank, sev_rank, f_id)

    return sorted(findings_list, key=sort_key)


class ScanHistory(models.Model):
    id = models.CharField(primary_key=True, max_length=64, default=generate_object_id, editable=False)
    score = models.FloatField()
    scannedResources = models.IntegerField()
    totalChecks = models.IntegerField(default=0, null=True, blank=True)
    skippedChecks = models.TextField(null=True, blank=True)
    criticalCount = models.IntegerField(default=0)
    highCount = models.IntegerField(default=0)
    mediumCount = models.IntegerField(default=0)
    findings = models.TextField()  # Stored as JSON string
    createdAt = models.DateTimeField(default=timezone.now)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="scans", db_column="projectId")

    def to_dict(self, include_project=False, parse_findings=False):
        parsed_findings = None
        if parse_findings and self.findings:
            try:
                raw = json.loads(self.findings)
                parsed_findings = sort_findings_list(raw)
            except Exception:
                parsed_findings = self.findings

        data = {
            "id": self.id,
            "score": self.score,
            "scannedResources": self.scannedResources,
            "totalChecks": self.totalChecks,
            "skippedChecks": self.skippedChecks,
            "criticalCount": self.criticalCount,
            "highCount": self.highCount,
            "mediumCount": self.mediumCount,
            "findings": parsed_findings if parse_findings else self.findings,
            "createdAt": self.createdAt.isoformat() if self.createdAt else None,
            "projectId": self.project_id,
        }
        if include_project and self.project:
            data["project"] = self.project.to_dict()
        return data

    def __str__(self):
        return f"Scan {self.id} for {self.project.name} - Score: {self.score}%"
