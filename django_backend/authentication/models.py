import uuid
from django.db import models
from django.utils import timezone


def generate_object_id():
    return uuid.uuid4().hex[:24]


class User(models.Model):
    id = models.CharField(primary_key=True, max_length=64, default=generate_object_id, editable=False)
    email = models.EmailField(unique=True)
    passwordHash = models.CharField(max_length=255)
    name = models.CharField(max_length=255, null=True, blank=True)
    displayPicture = models.TextField(null=True, blank=True)
    createdAt = models.DateTimeField(default=timezone.now)
    isVerified = models.BooleanField(default=False)
    otp = models.CharField(max_length=10, null=True, blank=True)
    otpExpiry = models.DateTimeField(null=True, blank=True)

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "displayPicture": self.displayPicture,
            "isVerified": self.isVerified,
            "createdAt": self.createdAt.isoformat() if self.createdAt else None,
        }

    def __str__(self):
        return self.email
