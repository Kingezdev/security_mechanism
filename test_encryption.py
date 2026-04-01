#!/usr/bin/env python
"""
Manual testing script for encryption functionality
Run with: python test_encryption.py
"""

import os
import sys
import django
from io import BytesIO

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from django.contrib.auth.models import User
from encryption.models import EncryptionAlgorithm, EncryptionKey, IntegrityCheck, KeyUsageLog
from encryption.services import EncryptionService
from django.core.files.uploadedfile import SimpleUploadedFile


def create_test_data():
    """Create test data for encryption testing"""
    print("🔧 Setting up test data...")
    
    # Create test user
    user, created = User.objects.get_or_create(
        username='testuser',
        defaults={'email': 'test@example.com', 'is_staff': True}
    )
    if created:
        user.set_password('testpass123')
        user.save()
        print(f"✅ Created test user: {user.username}")
    else:
        print(f"📋 Using existing test user: {user.username}")
    
    # Create encryption algorithms
    fernet_algo, created = EncryptionAlgorithm.objects.get_or_create(
        name='Fernet Standard',
        defaults={
            'slug': 'fernet-standard',
            'mode': 'fernet',
            'description': 'Fernet encryption for standard security documents',
            'key_size': 256,
            'is_active': True
        }
    )
    if created:
        print(f"✅ Created Fernet algorithm: {fernet_algo.name}")
    
    aes_cbc_algo, created = EncryptionAlgorithm.objects.get_or_create(
        name='AES-256 CBC',
        defaults={
            'slug': 'aes-256-cbc',
            'mode': 'aes_cbc',
            'description': 'AES-256 CBC mode for high-security documents',
            'key_size': 2048,  # RSA needs at least 1024, use 2048 for better security
            'is_active': True
        }
    )
    if created:
        print(f"✅ Created AES-CBC algorithm: {aes_cbc_algo.name}")
    
    return user, fernet_algo, aes_cbc_algo


def test_symmetric_key_generation():
    """Test symmetric key generation"""
    print("\n🔑 Testing Symmetric Key Generation...")
    
    user, fernet_algo, aes_cbc_algo = create_test_data()
    
    # Test Fernet key generation
    try:
        fernet_key = EncryptionKey.generate_symmetric_key(
            algorithm=fernet_algo,
            name="Test Fernet Key",
            created_by=user
        )
        print(f"✅ Fernet key generated: {fernet_key.name}")
        print(f"   Key ID: {fernet_key.id}")
        print(f"   Algorithm: {fernet_key.algorithm.name}")
        print(f"   Is Valid: {fernet_key.is_valid}")
    except Exception as e:
        print(f"❌ Fernet key generation failed: {e}")
        return False
    
    # Test AES-CBC key generation
    try:
        aes_key = EncryptionKey.generate_symmetric_key(
            algorithm=aes_cbc_algo,
            name="Test AES Key",
            created_by=user
        )
        print(f"✅ AES key generated: {aes_key.name}")
        print(f"   Key ID: {aes_key.id}")
        print(f"   Algorithm: {aes_key.algorithm.name}")
        print(f"   Is Valid: {aes_key.is_valid}")
    except Exception as e:
        print(f"❌ AES key generation failed: {e}")
        return False
    
    return True, fernet_key, aes_key


def test_asymmetric_key_generation():
    """Test asymmetric key pair generation"""
    print("\n🔐 Testing Asymmetric Key Pair Generation...")
    
    user, fernet_algo, aes_cbc_algo = create_test_data()
    
    try:
        private_key, public_key = EncryptionKey.generate_asymmetric_key_pair(
            algorithm=aes_cbc_algo,  # Use AES algorithm for RSA
            name_prefix="Test RSA",
            created_by=user
        )
        print(f"✅ RSA key pair generated:")
        print(f"   Private Key: {private_key.name} (ID: {private_key.id})")
        print(f"   Public Key: {public_key.name} (ID: {public_key.id})")
        print(f"   Private Key Valid: {private_key.is_valid}")
        print(f"   Public Key Valid: {public_key.is_valid}")
        return True, private_key, public_key
    except Exception as e:
        print(f"❌ RSA key pair generation failed: {e}")
        return False, None, None


def test_file_encryption():
    """Test file encryption functionality"""
    print("\n🔒 Testing File Encryption...")
    
    user, fernet_algo, aes_cbc_algo = create_test_data()
    success, fernet_key, aes_key = test_symmetric_key_generation()
    
    if not success:
        return False
    
    # Create test file content
    test_content = b"This is a test file for encryption. It contains sensitive data that should be protected."
    test_file = SimpleUploadedFile("test_document.txt", test_content, content_type="text/plain")
    
    print(f"📄 Original file size: {len(test_content)} bytes")
    print(f"📄 Original content: {test_content.decode()}")
    
    # Test Fernet encryption
    try:
        encrypted_file, success, error = EncryptionService.encrypt_file(
            test_file, fernet_key, user=user
        )
        if success:
            print(f"✅ Fernet encryption successful")
            print(f"   Encrypted file size: {len(encrypted_file.read())} bytes")
            encrypted_file.seek(0)  # Reset file pointer
        else:
            print(f"❌ Fernet encryption failed: {error}")
            return False
    except Exception as e:
        print(f"❌ Fernet encryption error: {e}")
        return False
    
    # Test AES-CBC encryption
    try:
        encrypted_file_aes, success, error = EncryptionService.encrypt_file(
            test_file, aes_key, user=user
        )
        if success:
            print(f"✅ AES-CBC encryption successful")
            print(f"   Encrypted file size: {len(encrypted_file_aes.read())} bytes")
            encrypted_file_aes.seek(0)  # Reset file pointer
        else:
            print(f"❌ AES-CBC encryption failed: {error}")
            return False
    except Exception as e:
        print(f"❌ AES-CBC encryption error: {e}")
        return False
    
    return True, encrypted_file, encrypted_file_aes


def test_file_decryption():
    """Test file decryption functionality"""
    print("\n🔓 Testing File Decryption...")
    
    user, fernet_algo, aes_cbc_algo = create_test_data()
    success, fernet_key, aes_key = test_symmetric_key_generation()
    
    if not success:
        return False
    
    # Create and encrypt test file
    test_content = b"This is a test file for encryption and decryption testing."
    test_file = SimpleUploadedFile("test_document.txt", test_content, content_type="text/plain")
    
    # Encrypt with Fernet
    encrypted_file, success, error = EncryptionService.encrypt_file(
        test_file, fernet_key, user=user
    )
    if not success:
        print(f"❌ Encryption failed, cannot test decryption: {error}")
        return False
    
    # Test Fernet decryption
    try:
        decrypted_file, success, error = EncryptionService.decrypt_file(
            encrypted_file, fernet_key, user=user
        )
        if success:
            decrypted_content = decrypted_file.read()
            print(f"✅ Fernet decryption successful")
            print(f"   Decrypted content: {decrypted_content.decode()}")
            print(f"   Content matches original: {decrypted_content == test_content}")
        else:
            print(f"❌ Fernet decryption failed: {error}")
            return False
    except Exception as e:
        print(f"❌ Fernet decryption error: {e}")
        return False
    
    return True


def test_integrity_checks():
    """Test integrity checking functionality"""
    print("\n🔍 Testing Integrity Checks...")
    
    user, fernet_algo, aes_cbc_algo = create_test_data()
    success, fernet_key, aes_key = test_symmetric_key_generation()
    
    if not success:
        return False
    
    # Create test file
    test_content = b"This is a test file for integrity checking."
    test_file = SimpleUploadedFile("integrity_test.txt", test_content, content_type="text/plain")
    
    # Encrypt file (this should create integrity check)
    encrypted_file, success, error = EncryptionService.encrypt_file(
        test_file, fernet_key, user=user
    )
    
    if success:
        # Check if integrity check was created
        integrity_checks = IntegrityCheck.objects.filter(
            encryption_key=fernet_key,
            user=user
        )
        if integrity_checks.exists():
            check = integrity_checks.first()
            print(f"✅ Integrity check created:")
            print(f"   File Path: {check.file_path}")
            print(f"   Original Checksum: {check.original_checksum}")
            print(f"   Encrypted Checksum: {check.encrypted_checksum}")
            print(f"   Check Passed: {check.check_passed}")
            print(f"   Timestamp: {check.check_timestamp}")
        else:
            print(f"❌ No integrity check found after encryption")
            return False
    else:
        print(f"❌ Encryption failed: {error}")
        return False
    
    return True


def test_key_lifecycle():
    """Test key lifecycle operations"""
    print("\n🔄 Testing Key Lifecycle...")
    
    user, fernet_algo, aes_cbc_algo = create_test_data()
    success, fernet_key, aes_key = test_symmetric_key_generation()
    
    if not success:
        return False
    
    # Test key revocation
    try:
        fernet_key.revoke(revoked_by=user)
        print(f"✅ Key revoked successfully")
        print(f"   Is Active: {fernet_key.is_active}")
        print(f"   Is Revoked: {fernet_key.is_revoked}")
        print(f"   Is Valid: {fernet_key.is_valid}")
        print(f"   Revoked At: {fernet_key.revoked_at}")
    except Exception as e:
        print(f"❌ Key revocation failed: {e}")
        return False
    
    # Test key reactivation
    try:
        fernet_key.activate()
        print(f"✅ Key reactivated successfully")
        print(f"   Is Active: {fernet_key.is_active}")
        print(f"   Is Valid: {fernet_key.is_valid}")
    except Exception as e:
        print(f"❌ Key activation failed: {e}")
        return False
    
    # Test key rotation
    try:
        new_key, success, error = EncryptionService.rotate_key(
            fernet_key, rotated_by=user
        )
        if success:
            print(f"✅ Key rotation successful")
            print(f"   New Key: {new_key.name}")
            print(f"   New Key ID: {new_key.id}")
            print(f"   Old Key Revoked: {fernet_key.is_revoked}")
        else:
            print(f"❌ Key rotation failed: {error}")
            return False
    except Exception as e:
        print(f"❌ Key rotation error: {e}")
        return False
    
    return True


def test_audit_logging():
    """Test audit logging functionality"""
    print("\n📊 Testing Audit Logging...")
    
    user, fernet_algo, aes_cbc_algo = create_test_data()
    
    # Clear previous logs for this user
    KeyUsageLog.objects.filter(user=user).delete()
    
    # Perform various operations
    success, fernet_key, aes_key = test_symmetric_key_generation()
    
    if success:
        # Check logs
        logs = KeyUsageLog.objects.filter(user=user)
        print(f"✅ Audit logs created:")
        for log in logs:
            print(f"   Action: {log.action}")
            print(f"   Key: {log.key.name}")
            print(f"   Success: {log.success}")
            print(f"   Timestamp: {log.timestamp}")
            print(f"   ---")
    
    return True


def run_all_tests():
    """Run all encryption tests"""
    print("🚀 Starting Encryption Functionality Tests")
    print("=" * 50)
    
    tests = [
        ("Symmetric Key Generation", test_symmetric_key_generation),
        ("Asymmetric Key Generation", test_asymmetric_key_generation),
        ("File Encryption", test_file_encryption),
        ("File Decryption", test_file_decryption),
        ("Integrity Checks", test_integrity_checks),
        ("Key Lifecycle", test_key_lifecycle),
        ("Audit Logging", test_audit_logging),
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        print(f"\n🧪 Running: {test_name}")
        try:
            result = test_func()
            if isinstance(result, tuple):
                results[test_name] = result[0]  # First element is success boolean
            else:
                results[test_name] = result
        except Exception as e:
            print(f"❌ Test '{test_name}' crashed: {e}")
            results[test_name] = False
    
    # Summary
    print("\n" + "=" * 50)
    print("📋 TEST RESULTS SUMMARY")
    print("=" * 50)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{test_name:.<40} {status}")
        if result:
            passed += 1
    
    print(f"\n📊 Overall: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("🎉 All tests passed! Encryption system is working correctly.")
    else:
        print("⚠️  Some tests failed. Please check the errors above.")


if __name__ == "__main__":
    run_all_tests()
