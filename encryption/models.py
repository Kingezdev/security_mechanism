from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.signing import Signer
from django.core.exceptions import ValidationError
import uuid
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


class EncryptionAlgorithm(models.Model):
    """Configuration model for encryption algorithms"""
    ENCRYPTION_MODES = [
        ('fernet', 'Fernet (Standard Security)'),
        ('aes_cbc', 'AES-CBC (High Security)'),
    ]
    
    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=100, unique=True)
    mode = models.CharField(max_length=20, choices=ENCRYPTION_MODES, default='fernet')
    description = models.TextField(blank=True)
    key_size = models.IntegerField(help_text="Key size in bits")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Encryption Algorithm"
        verbose_name_plural = "Encryption Algorithms"

    def __str__(self):
        return f"{self.name} ({self.key_size} bits) - {self.get_mode_display()}"


class EncryptionKey(models.Model):
    """Model for storing encryption keys"""
    KEY_TYPES = [
        ('symmetric', 'Symmetric Key'),
        ('asymmetric_public', 'Asymmetric Public Key'),
        ('asymmetric_private', 'Asymmetric Private Key'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    algorithm = models.ForeignKey(EncryptionAlgorithm, on_delete=models.PROTECT)
    name = models.CharField(max_length=200)
    key_type = models.CharField(max_length=20, choices=KEY_TYPES, default='symmetric')
    key_data = models.TextField(help_text="Encrypted key data")
    salt = models.CharField(max_length=64, blank=True)
    iv = models.CharField(max_length=64, blank=True, help_text="Initialization vector")
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='revoked_keys')

    class Meta:
        verbose_name = "Encryption Key"
        verbose_name_plural = "Encryption Keys"

    def __str__(self):
        return f"{self.name} ({self.algorithm.name}) - {'Active' if self.is_active else 'Inactive'}"

    def clean(self):
        """Validate key data"""
        if self.expires_at and self.expires_at <= timezone.now():
            raise ValidationError("Expiry date must be in the future")

    @property
    def is_expired(self):
        """Check if key is expired"""
        return self.expires_at and self.expires_at <= timezone.now()

    @property
    def is_revoked(self):
        """Check if key is revoked"""
        return self.revoked_at is not None

    @property
    def is_valid(self):
        """Check if key is valid (active, not expired, not revoked)"""
        return self.is_active and not self.is_expired and not self.is_revoked

    def mark_as_used(self):
        """Mark the key as used"""
        self.last_used_at = timezone.now()
        self.save(update_fields=['last_used_at'])

    def activate(self):
        """Activate the key"""
        self.is_active = True
        self.save(update_fields=['is_active'])

    def revoke(self, revoked_by=None):
        """Revoke the key"""
        self.is_active = False
        self.revoked_at = timezone.now()
        if revoked_by:
            self.revoked_by = revoked_by
        self.save(update_fields=['is_active', 'revoked_at', 'revoked_by'])

    @classmethod
    def wrap_key_data(cls, key_data, secret_key=None):
        """Wrap key data using Django's signing module"""
        if secret_key is None:
            from django.conf import settings
            secret_key = settings.SECRET_KEY
        
        # Use Django's default signer with SECRET_KEY from settings
        signer = Signer()
        # Convert bytes to base64 string for signing
        if isinstance(key_data, bytes):
            key_data = base64.b64encode(key_data).decode()
        
        return signer.sign(key_data)

    @classmethod
    def unwrap_key_data(cls, wrapped_key_data, secret_key=None):
        """Unwrap key data using Django's signing module"""
        if secret_key is None:
            from django.conf import settings
            secret_key = settings.SECRET_KEY
        
        # Use Django's default signer with SECRET_KEY from settings
        signer = Signer()
        try:
            unwrapped = signer.unsign(wrapped_key_data)
            # Convert back to bytes if it was base64 encoded
            try:
                return base64.b64decode(unwrapped.encode())
            except:
                return unwrapped.encode()
        except:
            raise ValueError("Invalid or corrupted key data")

    @classmethod
    def generate_symmetric_key(cls, algorithm, name, created_by=None, expires_at=None):
        """Generate a new symmetric encryption key"""
        if algorithm.mode == 'fernet':
            raw_key = Fernet.generate_key()
        else:
            import os
            raw_key = os.urandom(algorithm.key_size // 8)
        
        # Wrap the key using Django signing
        wrapped_key = cls.wrap_key_data(raw_key)
        
        key = cls.objects.create(
            algorithm=algorithm,
            name=name,
            key_type='symmetric',
            key_data=wrapped_key,
            created_by=created_by,
            expires_at=expires_at
        )
        
        # Log key generation
        from .services import KeyUsageLog
        KeyUsageLog.objects.create(
            key=key,
            user=created_by,
            action='generate',
            success=True
        )
        
        return key

    @classmethod
    def generate_asymmetric_key_pair(cls, algorithm, name_prefix, created_by=None, expires_at=None):
        """Generate a new asymmetric key pair"""
        # For RSA, ensure minimum key size
        key_size = max(algorithm.key_size, 1024)  # Ensure at least 1024 bits
        
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Wrap keys using Django signing
        wrapped_private = cls.wrap_key_data(private_pem)
        wrapped_public = cls.wrap_key_data(public_pem)
        
        # Create key records
        private_key_obj = cls.objects.create(
            algorithm=algorithm,
            name=f"{name_prefix}_private",
            key_type='asymmetric_private',
            key_data=wrapped_private,
            created_by=created_by,
            expires_at=expires_at
        )
        
        public_key_obj = cls.objects.create(
            algorithm=algorithm,
            name=f"{name_prefix}_public",
            key_type='asymmetric_public',
            key_data=wrapped_public,
            created_by=created_by,
            expires_at=expires_at
        )
        
        # Log key generation
        from .services import KeyUsageLog
        KeyUsageLog.objects.create(
            key=private_key_obj,
            user=created_by,
            action='generate',
            success=True
        )
        
        return private_key_obj, public_key_obj

    def get_unwrapped_key(self):
        """Get the unwrapped key data"""
        return self.unwrap_key_data(self.key_data)


class IntegrityCheck(models.Model):
    """Model for storing file integrity checksums"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file_path = models.CharField(max_length=500)
    original_checksum = models.CharField(max_length=64, help_text="SHA-256 checksum of original file")
    encrypted_checksum = models.CharField(max_length=64, blank=True, help_text="SHA-256 checksum of encrypted file")
    decrypted_checksum = models.CharField(max_length=64, blank=True, help_text="SHA-256 checksum after decryption")
    encryption_key = models.ForeignKey(EncryptionKey, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    check_passed = models.BooleanField(default=True)
    check_timestamp = models.DateTimeField(auto_now_add=True)
    failure_reason = models.TextField(blank=True)

    class Meta:
        verbose_name = "Integrity Check"
        verbose_name_plural = "Integrity Checks"
        ordering = ['-check_timestamp']

    def __str__(self):
        return f"Integrity Check for {self.file_path} - {'PASSED' if self.check_passed else 'FAILED'}"

    @classmethod
    def compute_checksum(cls, file_data):
        """Compute SHA-256 checksum of file data"""
        import hashlib
        return hashlib.sha256(file_data).hexdigest()

    @classmethod
    def verify_integrity(cls, file_path, original_data, processed_data, encryption_key=None, user=None):
        """
        Verify integrity between original and processed data
        
        Args:
            file_path: Path or name of the file
            original_data: Original file data (bytes)
            processed_data: Processed file data (bytes - encrypted or decrypted)
            encryption_key: EncryptionKey used (optional)
            user: User who performed the operation (optional)
            
        Returns:
            tuple: (integrity_check_instance, passed, error_message)
        """
        try:
            original_checksum = cls.compute_checksum(original_data)
            processed_checksum = cls.compute_checksum(processed_data)
            
            # For encrypted files, we expect checksums to differ
            # For decrypted files, we expect checksums to match
            is_decryption = encryption_key and hasattr(encryption_key, '_decryption_operation')
            
            if is_decryption:
                check_passed = original_checksum == processed_checksum
                failure_reason = "Decrypted file checksum mismatch" if not check_passed else ""
            else:
                # For encryption, we just store both checksums
                check_passed = True
                failure_reason = ""
            
            integrity_check = cls.objects.create(
                file_path=file_path,
                original_checksum=original_checksum,
                encrypted_checksum=processed_checksum if not is_decryption else "",
                decrypted_checksum=processed_checksum if is_decryption else "",
                encryption_key=encryption_key,
                user=user,
                check_passed=check_passed,
                failure_reason=failure_reason
            )
            
            # Log integrity failure to audit log
            if not check_passed:
                KeyUsageLog.objects.create(
                    key=encryption_key,
                    user=user,
                    action='INTEGRITY_FAIL',
                    file_path=file_path,
                    success=False,
                    error_message=f"Integrity check failed: {failure_reason}",
                )
            
            return integrity_check, check_passed, None if check_passed else failure_reason
            
        except Exception as e:
            error_msg = f"Integrity check error: {str(e)}"
            # Log the integrity check failure
            KeyUsageLog.objects.create(
                key=encryption_key,
                user=user,
                action='INTEGRITY_FAIL',
                file_path=file_path,
                success=False,
                error_message=error_msg,
            )
            return None, False, error_msg


class KeyUsageLog(models.Model):
    """Model for logging key usage"""
    key = models.ForeignKey(EncryptionKey, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=20, choices=[
        ('encrypt', 'Encrypt'),
        ('decrypt', 'Decrypt'),
        ('generate', 'Generate'),
        ('rotate', 'Rotate'),
        ('revoke', 'Revoke'),
        ('INTEGRITY_FAIL', 'Integrity Failure'),
    ])
    file_path = models.CharField(max_length=500, blank=True)
    file_size = models.BigIntegerField(null=True, blank=True)
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Key Usage Log"
        verbose_name_plural = "Key Usage Logs"
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.user.username if self.user else 'System'} - {self.action} - {self.timestamp}"
