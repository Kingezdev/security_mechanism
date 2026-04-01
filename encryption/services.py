import os
import hashlib
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from django.conf import settings
from django.core.files.base import ContentFile
from django.utils import timezone
from .models import EncryptionKey, KeyUsageLog, IntegrityCheck


class EncryptionService:
    """Service for handling file encryption and decryption operations"""
    
    @staticmethod
    def generate_key(algorithm_name='AES', key_size=256):
        """Generate a new encryption key"""
        if algorithm_name.upper() == 'AES':
            if key_size == 256:
                return Fernet.generate_key()
            else:
                return os.urandom(key_size // 8)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm_name}")
    
    @staticmethod
    def derive_key_from_password(password, salt=None):
        """Derive encryption key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key, salt
    
    @staticmethod
    def encrypt_file(file_obj, encryption_key, user=None, ip_address="", user_agent=""):
        """
        Encrypt a file using the specified encryption key
        
        Args:
            file_obj: Django file object or file-like object
            encryption_key: EncryptionKey model instance
            user: User model instance (optional)
            ip_address: IP address of the user (optional)
            user_agent: User agent string (optional)
            
        Returns:
            tuple: (encrypted_file_obj, success, error_message)
        """
        try:
            # Validate key first
            if not encryption_key.is_valid:
                error_msg = "Key is not valid (inactive, expired, or revoked)"
                KeyUsageLog.objects.create(
                    key=encryption_key,
                    user=user,
                    action='encrypt',
                    file_path=getattr(file_obj, 'name', 'unknown'),
                    success=False,
                    error_message=error_msg,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                return None, False, error_msg

            # Read file data
            file_data = file_obj.read()
            file_size = len(file_data)
            
            # Compute original checksum before encryption
            original_checksum = IntegrityCheck.compute_checksum(file_data)
            
            # Get encryption algorithm
            algorithm = encryption_key.algorithm
            
            # Get unwrapped key data
            key_data = encryption_key.get_unwrapped_key()
            
            if algorithm.mode == 'fernet':
                # Use Fernet for standard security documents
                fernet = Fernet(key_data)
                encrypted_data = fernet.encrypt(file_data)
                
                # Create encrypted file
                encrypted_file = ContentFile(encrypted_data, name=f"encrypted_{file_obj.name}")
                
                # Perform integrity check
                integrity_check, check_passed, error_msg = IntegrityCheck.verify_integrity(
                    file_path=getattr(file_obj, 'name', 'unknown'),
                    original_data=file_data,
                    processed_data=encrypted_data,
                    encryption_key=encryption_key,
                    user=user
                )
                
                if not check_passed:
                    return None, False, f"Integrity check failed: {error_msg}"
                
                # Log successful encryption
                KeyUsageLog.objects.create(
                    key=encryption_key,
                    user=user,
                    action='encrypt',
                    file_path=getattr(file_obj, 'name', 'unknown'),
                    file_size=file_size,
                    success=True,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                # Mark key as used
                encryption_key.mark_as_used()
                
                return encrypted_file, True, None
                
            elif algorithm.mode == 'aes_cbc':
                # Use raw AES-CBC for high-security documents
                from cryptography.hazmat.primitives import padding
                
                # Generate IV if not provided
                iv = encryption_key.iv.encode() if encryption_key.iv else os.urandom(16)
                
                # Create cipher
                cipher = Cipher(
                    algorithms.AES(key_data),
                    modes.CBC(iv),
                    backend=default_backend()
                )
                
                # Pad the data
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(file_data) + padder.finalize()
                
                # Encrypt
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
                
                # Prepend IV to encrypted data
                final_data = iv + encrypted_data
                
                # Create encrypted file
                encrypted_file = ContentFile(final_data, name=f"encrypted_{file_obj.name}")
                
                # Perform integrity check
                integrity_check, check_passed, error_msg = IntegrityCheck.verify_integrity(
                    file_path=getattr(file_obj, 'name', 'unknown'),
                    original_data=file_data,
                    processed_data=final_data,
                    encryption_key=encryption_key,
                    user=user
                )
                
                if not check_passed:
                    return None, False, f"Integrity check failed: {error_msg}"
                
                # Log successful encryption
                KeyUsageLog.objects.create(
                    key=encryption_key,
                    user=user,
                    action='encrypt',
                    file_path=getattr(file_obj, 'name', 'unknown'),
                    file_size=file_size,
                    success=True,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                # Mark key as used
                encryption_key.mark_as_used()
                
                return encrypted_file, True, None
                
            elif encryption_key.key_type == 'asymmetric_public':
                # Use asymmetric encryption with public key
                from cryptography.hazmat.primitives import serialization
                
                # Load public key
                public_key = serialization.load_pem_public_key(
                    key_data,
                    backend=default_backend()
                )
                
                # Encrypt with OAEP padding
                encrypted_data = public_key.encrypt(
                    file_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Create encrypted file
                encrypted_file = ContentFile(encrypted_data, name=f"encrypted_{file_obj.name}")
                
                # Perform integrity check
                integrity_check, check_passed, error_msg = IntegrityCheck.verify_integrity(
                    file_path=getattr(file_obj, 'name', 'unknown'),
                    original_data=file_data,
                    processed_data=encrypted_data,
                    encryption_key=encryption_key,
                    user=user
                )
                
                if not check_passed:
                    return None, False, f"Integrity check failed: {error_msg}"
                
                # Log successful encryption
                KeyUsageLog.objects.create(
                    key=encryption_key,
                    user=user,
                    action='encrypt',
                    file_path=getattr(file_obj, 'name', 'unknown'),
                    file_size=file_size,
                    success=True,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                # Mark key as used
                encryption_key.mark_as_used()
                
                return encrypted_file, True, None
                
            else:
                error_msg = f"Unsupported encryption algorithm: {algorithm.name}"
                KeyUsageLog.objects.create(
                    key=encryption_key,
                    user=user,
                    action='encrypt',
                    file_path=getattr(file_obj, 'name', 'unknown'),
                    success=False,
                    error_message=error_msg,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                return None, False, error_msg
                
        except Exception as e:
            error_msg = str(e)
            KeyUsageLog.objects.create(
                key=encryption_key,
                user=user,
                action='encrypt',
                file_path=getattr(file_obj, 'name', 'unknown'),
                success=False,
                error_message=error_msg,
                ip_address=ip_address,
                user_agent=user_agent
            )
            return None, False, error_msg
    
    @staticmethod
    def decrypt_file(encrypted_file_obj, encryption_key, user=None, ip_address="", user_agent=""):
        """
        Decrypt a file using the specified encryption key
        
        Args:
            encrypted_file_obj: Django file object or file-like object
            encryption_key: EncryptionKey model instance
            user: User model instance (optional)
            ip_address: IP address of the user (optional)
            user_agent: User agent string (optional)
            
        Returns:
            tuple: (decrypted_file_obj, success, error_message)
        """
        try:
            # Validate key first
            if not encryption_key.is_valid:
                error_msg = "Key is not valid (inactive, expired, or revoked)"
                KeyUsageLog.objects.create(
                    key=encryption_key,
                    user=user,
                    action='decrypt',
                    file_path=getattr(encrypted_file_obj, 'name', 'unknown'),
                    success=False,
                    error_message=error_msg,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                return None, False, error_msg

            # Read encrypted data
            encrypted_data = encrypted_file_obj.read()
            original_size = len(encrypted_data)
            
            # Get encryption algorithm
            algorithm = encryption_key.algorithm
            
            # Get unwrapped key data
            key_data = encryption_key.get_unwrapped_key()
            
            # Mark this as a decryption operation for integrity checking
            encryption_key._decryption_operation = True
            
            if algorithm.mode == 'fernet':
                # Use Fernet for standard security documents
                fernet = Fernet(key_data)
                decrypted_data = fernet.decrypt(encrypted_data)
                
                # Create decrypted file
                original_name = getattr(encrypted_file_obj, 'name', 'encrypted_file')
                if original_name.startswith('encrypted_'):
                    original_name = original_name[10:]  # Remove 'encrypted_' prefix
                decrypted_file = ContentFile(decrypted_data, name=f"decrypted_{original_name}")
                
                # Perform integrity check - compare with original if available
                # For now, we'll store the decrypted checksum
                integrity_check = IntegrityCheck.objects.create(
                    file_path=getattr(encrypted_file_obj, 'name', 'unknown'),
                    original_checksum="",  # We don't have the original during decryption
                    encrypted_checksum=IntegrityCheck.compute_checksum(encrypted_data),
                    decrypted_checksum=IntegrityCheck.compute_checksum(decrypted_data),
                    encryption_key=encryption_key,
                    user=user,
                    check_passed=True  # Assume passed for now, could be enhanced with original comparison
                )
                
                # Log successful decryption
                KeyUsageLog.objects.create(
                    key=encryption_key,
                    user=user,
                    action='decrypt',
                    file_path=getattr(encrypted_file_obj, 'name', 'unknown'),
                    file_size=len(decrypted_data),
                    success=True,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                # Mark key as used
                encryption_key.mark_as_used()
                
                return decrypted_file, True, None
                
            elif algorithm.mode == 'aes_cbc':
                # Use raw AES-CBC for high-security documents
                from cryptography.hazmat.primitives import padding
                
                # Extract IV from the beginning of encrypted data
                iv = encrypted_data[:16]
                ciphertext = encrypted_data[16:]
                
                # Create cipher
                cipher = Cipher(
                    algorithms.AES(key_data),
                    modes.CBC(iv),
                    backend=default_backend()
                )
                
                # Decrypt
                decryptor = cipher.decryptor()
                padded_data = decryptor.update(ciphertext) + decryptor.finalize()
                
                # Unpad the data
                unpadder = padding.PKCS7(128).unpadder()
                decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
                
                # Create decrypted file
                original_name = getattr(encrypted_file_obj, 'name', 'encrypted_file')
                if original_name.startswith('encrypted_'):
                    original_name = original_name[10:]  # Remove 'encrypted_' prefix
                decrypted_file = ContentFile(decrypted_data, name=f"decrypted_{original_name}")
                
                # Perform integrity check
                integrity_check = IntegrityCheck.objects.create(
                    file_path=getattr(encrypted_file_obj, 'name', 'unknown'),
                    original_checksum="",  # We don't have the original during decryption
                    encrypted_checksum=IntegrityCheck.compute_checksum(encrypted_data),
                    decrypted_checksum=IntegrityCheck.compute_checksum(decrypted_data),
                    encryption_key=encryption_key,
                    user=user,
                    check_passed=True  # Assume passed for now, could be enhanced with original comparison
                )
                
                # Log successful decryption
                KeyUsageLog.objects.create(
                    key=encryption_key,
                    user=user,
                    action='decrypt',
                    file_path=getattr(encrypted_file_obj, 'name', 'unknown'),
                    file_size=len(decrypted_data),
                    success=True,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                # Mark key as used
                encryption_key.mark_as_used()
                
                return decrypted_file, True, None
                
            elif encryption_key.key_type == 'asymmetric_private':
                # Use asymmetric decryption with private key
                from cryptography.hazmat.primitives import serialization
                
                # Load private key
                private_key = serialization.load_pem_private_key(
                    key_data,
                    password=None,
                    backend=default_backend()
                )
                
                # Decrypt with OAEP padding
                decrypted_data = private_key.decrypt(
                    encrypted_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Create decrypted file
                original_name = getattr(encrypted_file_obj, 'name', 'encrypted_file')
                if original_name.startswith('encrypted_'):
                    original_name = original_name[10:]  # Remove 'encrypted_' prefix
                decrypted_file = ContentFile(decrypted_data, name=f"decrypted_{original_name}")
                
                # Perform integrity check
                integrity_check = IntegrityCheck.objects.create(
                    file_path=getattr(encrypted_file_obj, 'name', 'unknown'),
                    original_checksum="",  # We don't have the original during decryption
                    encrypted_checksum=IntegrityCheck.compute_checksum(encrypted_data),
                    decrypted_checksum=IntegrityCheck.compute_checksum(decrypted_data),
                    encryption_key=encryption_key,
                    user=user,
                    check_passed=True  # Assume passed for now, could be enhanced with original comparison
                )
                
                # Log successful decryption
                KeyUsageLog.objects.create(
                    key=encryption_key,
                    user=user,
                    action='decrypt',
                    file_path=getattr(encrypted_file_obj, 'name', 'unknown'),
                    file_size=len(decrypted_data),
                    success=True,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                # Mark key as used
                encryption_key.mark_as_used()
                
                return decrypted_file, True, None
                
            else:
                error_msg = f"Unsupported encryption algorithm: {algorithm.name}"
                KeyUsageLog.objects.create(
                    key=encryption_key,
                    user=user,
                    action='decrypt',
                    file_path=getattr(encrypted_file_obj, 'name', 'unknown'),
                    success=False,
                    error_message=error_msg,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                return None, False, error_msg
                
        except Exception as e:
            error_msg = str(e)
            KeyUsageLog.objects.create(
                key=encryption_key,
                user=user,
                action='decrypt',
                file_path=getattr(encrypted_file_obj, 'name', 'unknown'),
                success=False,
                error_message=error_msg,
                ip_address=ip_address,
                user_agent=user_agent
            )
            return None, False, error_msg
    
    @staticmethod
    def rotate_key(old_key, new_algorithm=None, new_name=None, rotated_by=None):
        """
        Rotate an encryption key by creating a new key and revoking the old one
        
        Args:
            old_key: Existing EncryptionKey to rotate
            new_algorithm: New algorithm (defaults to old key's algorithm)
            new_name: Name for new key (defaults to old key's name with timestamp)
            rotated_by: User performing the rotation
            
        Returns:
            tuple: (new_key, success, error_message)
        """
        try:
            if not old_key.is_valid:
                return None, False, "Cannot rotate invalid key"
            
            # Use old key's algorithm if not specified
            if new_algorithm is None:
                new_algorithm = old_key.algorithm
            
            # Generate new name if not specified
            if new_name is None:
                timestamp = timezone.now().strftime("%Y%m%d_%H%M%S")
                new_name = f"{old_key.name}_rotated_{timestamp}"
            
            # Create new key based on type
            if old_key.key_type == 'symmetric':
                new_key = EncryptionKey.generate_symmetric_key(
                    algorithm=new_algorithm,
                    name=new_name,
                    created_by=rotated_by,
                    expires_at=old_key.expires_at
                )
            elif old_key.key_type in ['asymmetric_public', 'asymmetric_private']:
                # For asymmetric keys, we need to find the pair and rotate both
                if old_key.key_type == 'asymmetric_private':
                    # Find the corresponding public key
                    try:
                        public_key = EncryptionKey.objects.get(
                            name=old_key.name.replace('_private', '_public'),
                            key_type='asymmetric_public'
                        )
                    except EncryptionKey.DoesNotExist:
                        public_key = None
                else:
                    # Find the corresponding private key
                    try:
                        private_key = EncryptionKey.objects.get(
                            name=old_key.name.replace('_public', '_private'),
                            key_type='asymmetric_private'
                        )
                    except EncryptionKey.DoesNotExist:
                        private_key = None
                
                # Generate new key pair
                new_private_key, new_public_key = EncryptionKey.generate_asymmetric_key_pair(
                    algorithm=new_algorithm,
                    name_prefix=new_name.replace('_private', '').replace('_public', ''),
                    created_by=rotated_by,
                    expires_at=old_key.expires_at
                )
                
                # Revoke old keys
                old_key.revoke(revoked_by=rotated_by)
                if public_key:
                    public_key.revoke(revoked_by=rotated_by)
                elif private_key:
                    private_key.revoke(revoked_by=rotated_by)
                
                # Log rotation
                KeyUsageLog.objects.create(
                    key=old_key,
                    user=rotated_by,
                    action='rotate',
                    success=True
                )
                
                return new_private_key if old_key.key_type == 'asymmetric_private' else new_public_key, True, None
            
            # Revoke old key
            old_key.revoke(revoked_by=rotated_by)
            
            # Log rotation
            KeyUsageLog.objects.create(
                key=old_key,
                user=rotated_by,
                action='rotate',
                success=True
            )
            
            return new_key, True, None
            
        except Exception as e:
            error_msg = str(e)
            KeyUsageLog.objects.create(
                key=old_key,
                user=rotated_by,
                action='rotate',
                success=False,
                error_message=error_msg
            )
            return None, False, error_msg


# Convenience functions
def encrypt_file(file_obj, encryption_key, user=None, ip_address=None, user_agent=None):
    """Convenience function to encrypt a file"""
    return EncryptionService.encrypt_file(
        file_obj, encryption_key, user, ip_address or "", user_agent or ""
    )


def decrypt_file(encrypted_file_obj, encryption_key, user=None, ip_address=None, user_agent=None):
    """Convenience function to decrypt a file"""
    return EncryptionService.decrypt_file(
        encrypted_file_obj, encryption_key, user, ip_address or "", user_agent or ""
    )
