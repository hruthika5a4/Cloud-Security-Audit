import json
from django.db import models
from django.utils import timezone
from authentication.models import User, generate_object_id
from projects.models import Project


class AuditSchedule(models.Model):
    id = models.CharField(primary_key=True, max_length=64, default=generate_object_id, editable=False)
    frequency = models.CharField(max_length=50)  # 'daily', 'weekly', 'monthly', 'once'
    time = models.CharField(max_length=10, null=True, blank=True)  # HH:mm format
    daysOfWeek = models.JSONField(default=list, null=True, blank=True)  # ["Monday", "Wednesday"]
    dayOfMonth = models.IntegerField(null=True, blank=True)  # 1 to 31
    credentials = models.TextField(null=True, blank=True)
    lastRun = models.DateTimeField(null=True, blank=True)
    nextRun = models.DateTimeField()
    targetEmail = models.EmailField(null=True, blank=True)
    isActive = models.BooleanField(default=True)
    createdAt = models.DateTimeField(default=timezone.now)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="schedules", db_column="userId")
    project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True, blank=True, related_name="schedules", db_column="projectId")

    def to_dict(self, include_project=True):
        days = self.daysOfWeek
        if isinstance(days, str):
            try:
                days = json.loads(days)
            except Exception:
                days = []
        elif days is None:
            days = []

        data = {
            "id": self.id,
            "frequency": self.frequency,
            "time": self.time,
            "daysOfWeek": days,
            "dayOfMonth": self.dayOfMonth,
            "credentials": self.credentials,
            "lastRun": self.lastRun.isoformat() if self.lastRun else None,
            "nextRun": self.nextRun.isoformat() if self.nextRun else None,
            "targetEmail": self.targetEmail,
            "isActive": self.isActive,
            "createdAt": self.createdAt.isoformat() if self.createdAt else None,
            "userId": self.user_id,
            "projectId": self.project_id,
        }
        if include_project and self.project:
            data["project"] = self.project.to_dict()
        else:
            data["project"] = None
        return data

    def __str__(self):
        return f"Schedule {self.id} ({self.frequency}) for {self.user.email}"
