from django.conf import settings
from django.db import models
from django.utils import timezone
from encryption.models import EncryptionKey, IntegrityCheck
from encryption.services import EncryptionService


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
    encryption_key = models.ForeignKey(
        EncryptionKey,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        help_text="Encryption key used for this document"
    )
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=['owner', 'is_deleted']),
            models.Index(fields=['category', 'created_at']),
        ]

    def __str__(self):
        return self.title
    
    def soft_delete(self):
        """Soft delete the document"""
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save()
    
    def restore(self):
        """Restore a soft-deleted document"""
        self.is_deleted = False
        self.deleted_at = None
        self.save()
    
    def get_latest_version(self):
        """Get the latest version of this document"""
        return self.versions.order_by('-version_number').first()
    
    def get_file_size_display(self):
        """Get human-readable file size"""
        latest_version = self.get_latest_version()
        if latest_version:
            size = latest_version.file_size
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size < 1024:
                    return f"{size:.1f} {unit}"
                size /= 1024
            return f"{size:.1f} TB"
        return "N/A"
    
    def encrypt_file_data(self, file_obj, user=None):
        """Encrypt file data using the document's encryption key"""
        if not self.encryption_key:
            return None, False, "No encryption key assigned"
        
        print(f"Encrypting with key: {self.encryption_key.name} (valid: {self.encryption_key.is_valid})")
        
        return EncryptionService.encrypt_file(
            file_obj, 
            self.encryption_key, 
            user=user,
            ip_address=getattr(user, '_ip_address', ''),
            user_agent=getattr(user, '_user_agent', '')
        )
    
    def decrypt_file_data(self, encrypted_file_obj, user=None):
        """Decrypt file data using the document's encryption key"""
        if not self.encryption_key:
            return None, False, "No encryption key assigned"
        
        return EncryptionService.decrypt_file(
            encrypted_file_obj,
            self.encryption_key,
            user=user,
            ip_address=getattr(user, '_ip_address', ''),
            user_agent=getattr(user, '_user_agent', '')
        )


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
    integrity_check = models.ForeignKey(
        IntegrityCheck,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="Integrity check result for this version"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ["-version_number"]
        unique_together = ("document", "version_number")
        indexes = [
            models.Index(fields=['document', 'version_number']),
        ]

    def __str__(self):
        return f"{self.document.title} - Version {self.version_number}"
    
    def get_next_version_number(self):
        """Get the next version number for this document"""
        latest = DocumentVersion.objects.filter(
            document=self.document
        ).order_by('-version_number').first()
        return (latest.version_number + 1) if latest else 1
    
    def verify_integrity(self):
        """Verify the integrity of this version"""
        if not self.integrity_check:
            return False, "No integrity check available"
        
        return self.integrity_check.check_passed, self.integrity_check.failure_reason