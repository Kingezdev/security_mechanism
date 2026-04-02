from django.conf import settings
from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model
from encryption.models import EncryptionKey, IntegrityCheck
from encryption.services import EncryptionService
import secrets
import uuid

User = get_user_model()


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


class DocumentShare(models.Model):
    """Model for sharing documents with secure tokens and permissions"""
    
    PERMISSION_CHOICES = [
        ('view', 'View Only'),
        ('download', 'View & Download'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    document = models.ForeignKey(
        Document,
        on_delete=models.CASCADE,
        related_name="shares",
    )
    shared_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="shared_documents",
    )
    share_token = models.CharField(
        max_length=64,
        unique=True,
        help_text="Secure token for accessing shared document"
    )
    permission = models.CharField(
        max_length=20,
        choices=PERMISSION_CHOICES,
        default='view',
        help_text="Permission level for shared access"
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the share link expires (null for no expiry)"
    )
    max_downloads = models.PositiveIntegerField(
        null=True,
        blank=True,
        help_text="Maximum number of downloads allowed (null for unlimited)"
    )
    download_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of times the document has been downloaded"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether the share link is active"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['share_token']),
            models.Index(fields=['document', 'is_active']),
            models.Index(fields=['expires_at']),
        ]
    
    def __str__(self):
        return f"{self.document.title} shared by {self.shared_by.username}"
    
    @classmethod
    def create_share(cls, document, shared_by, permission='view', expires_at=None, max_downloads=None):
        """Create a new document share with secure token"""
        # Generate secure token
        token = secrets.token_urlsafe(48)
        
        return cls.objects.create(
            document=document,
            shared_by=shared_by,
            share_token=token,
            permission=permission,
            expires_at=expires_at,
            max_downloads=max_downloads
        )
    
    def is_valid(self):
        """Check if the share link is still valid"""
        if not self.is_active:
            return False, "Share link has been deactivated"
        
        if self.expires_at and timezone.now() > self.expires_at:
            return False, "Share link has expired"
        
        if self.max_downloads and self.download_count >= self.max_downloads:
            return False, "Download limit exceeded"
        
        return True, "Share link is valid"
    
    def can_download(self):
        """Check if the user can download the document"""
        is_valid, message = self.is_valid()
        if not is_valid:
            return False, message
        
        if self.permission == 'view':
            return False, "Download not permitted with view-only permission"
        
        return True, "Download allowed"
    
    def increment_download_count(self):
        """Increment the download count"""
        self.download_count += 1
        self.save(update_fields=['download_count'])
    
    def get_share_url(self, request):
        """Get the full share URL"""
        return f"{request.scheme}://{request.get_host()}/documents/shared/{self.share_token}/"
    
    def revoke(self):
        """Revoke the share link"""
        self.is_active = False
        self.save(update_fields=['is_active'])