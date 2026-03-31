from django.conf import settings
from django.db import models


class Document(models.Model):
    CATEGORY_CHOICES = [
        ("academic", "Academic"),
        ("research", "Research"),
        ("personal", "Personal"),
        ("administrative", "Administrative"),
    ]

    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="documents",
    )
    category = models.CharField(
        max_length=50,
        choices=CATEGORY_CHOICES,
        default="academic",
    )
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.title


class DocumentVersion(models.Model):
    document = models.ForeignKey(
        Document,
        on_delete=models.CASCADE,
        related_name="versions",
    )
    version_number = models.PositiveIntegerField()
    encrypted_file = models.FileField(upload_to="documents/encrypted/")
    original_filename = models.CharField(max_length=255)
    checksum = models.CharField(max_length=128)
    file_size = models.PositiveBigIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-version_number"]
        unique_together = ("document", "version_number")

    def __str__(self):
        return f"{self.document.title} - Version {self.version_number}"