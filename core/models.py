from django.db import models


class LabUser(models.Model):
    # VULN: stores plaintext passwords intentionally.
    username = models.CharField(max_length=64, unique=True)
    password = models.CharField(max_length=128)
    role = models.CharField(max_length=16, default="user")
    api_token = models.CharField(max_length=128, default="token")

    def __str__(self):
        return self.username


class SecretRecord(models.Model):
    owner = models.ForeignKey(LabUser, on_delete=models.CASCADE, related_name="records")
    title = models.CharField(max_length=120)
    body = models.TextField()

    def __str__(self):
        return self.title


class GuestbookEntry(models.Model):
    name = models.CharField(max_length=64)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)


class UploadedDocument(models.Model):
    filename = models.CharField(max_length=255)
    file = models.FileField(upload_to="uploads/")
    uploaded_at = models.DateTimeField(auto_now_add=True)
