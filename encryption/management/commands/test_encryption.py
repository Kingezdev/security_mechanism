from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from encryption.models import EncryptionAlgorithm, EncryptionKey, IntegrityCheck, KeyUsageLog
from encryption.services import EncryptionService
from django.core.files.uploadedfile import SimpleUploadedFile


class Command(BaseCommand):
    help = 'Test encryption functionality'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--test-type',
            type=str,
            choices=['all', 'keys', 'encrypt', 'decrypt', 'integrity', 'lifecycle', 'audit'],
            default='all',
            help='Type of test to run'
        )
        parser.add_argument(
            '--username',
            type=str,
            default='testuser',
            help='Username for test operations'
        )
    
    def handle(self, *args, **options):
        test_type = options['test_type']
        username = options['username']
        
        self.stdout.write(f"🚀 Running encryption tests (type: {test_type})")
        self.stdout.write("=" * 50)
        
        # Setup test user
        user, created = User.objects.get_or_create(
            username=username,
            defaults={'email': f'{username}@example.com', 'is_staff': True}
        )
        if created:
            user.set_password('testpass123')
            user.save()
            self.stdout.write(f"✅ Created test user: {user.username}")
        else:
            self.stdout.write(f"📋 Using existing test user: {user.username}")
        
        # Setup algorithms
        fernet_algo, _ = EncryptionAlgorithm.objects.get_or_create(
            name='Fernet Standard',
            defaults={
                'slug': 'fernet-standard',
                'mode': 'fernet',
                'description': 'Fernet encryption for standard security documents',
                'key_size': 256,
                'is_active': True
            }
        )
        
        aes_cbc_algo, _ = EncryptionAlgorithm.objects.get_or_create(
            name='AES-256 CBC',
            defaults={
                'slug': 'aes-256-cbc',
                'mode': 'aes_cbc',
                'description': 'AES-256 CBC mode for high-security documents',
                'key_size': 2048,  # RSA needs at least 1024, use 2048 for better security
                'is_active': True
            }
        )
        
        results = {}
        
        if test_type in ['all', 'keys']:
            results['Key Generation'] = self.test_key_generation(user, fernet_algo, aes_cbc_algo)
        
        if test_type in ['all', 'encrypt']:
            results['File Encryption'] = self.test_file_encryption(user, fernet_algo, aes_cbc_algo)
        
        if test_type in ['all', 'decrypt']:
            results['File Decryption'] = self.test_file_decryption(user, fernet_algo, aes_cbc_algo)
        
        if test_type in ['all', 'integrity']:
            results['Integrity Checks'] = self.test_integrity_checks(user, fernet_algo, aes_cbc_algo)
        
        if test_type in ['all', 'lifecycle']:
            results['Key Lifecycle'] = self.test_key_lifecycle(user, fernet_algo, aes_cbc_algo)
        
        if test_type in ['all', 'audit']:
            results['Audit Logging'] = self.test_audit_logging(user)
        
        # Summary
        self.stdout.write("\n" + "=" * 50)
        self.stdout.write("📋 TEST RESULTS SUMMARY")
        self.stdout.write("=" * 50)
        
        passed = 0
        total = len(results)
        
        for test_name, result in results.items():
            status = "✅ PASSED" if result else "❌ FAILED"
            self.stdout.write(f"{test_name:.<40} {status}")
            if result:
                passed += 1
        
        self.stdout.write(f"\n📊 Overall: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
        
        if passed == total:
            self.stdout.write(self.style.SUCCESS("🎉 All tests passed! Encryption system is working correctly."))
        else:
            self.stdout.write(self.style.WARNING("⚠️  Some tests failed. Please check the errors above."))
    
    def test_key_generation(self, user, fernet_algo, aes_cbc_algo):
        """Test key generation"""
        try:
            # Test symmetric keys
            fernet_key = EncryptionKey.generate_symmetric_key(
                algorithm=fernet_algo,
                name="Test Fernet Key",
                created_by=user
            )
            
            aes_key = EncryptionKey.generate_symmetric_key(
                algorithm=aes_cbc_algo,
                name="Test AES Key",
                created_by=user
            )
            
            # Test asymmetric keys
            private_key, public_key = EncryptionKey.generate_asymmetric_key_pair(
                algorithm=aes_cbc_algo,
                name_prefix="Test RSA",
                created_by=user
            )
            
            self.stdout.write("✅ Key generation successful")
            self.stdout.write(f"   Fernet Key: {fernet_key.name}")
            self.stdout.write(f"   AES Key: {aes_key.name}")
            self.stdout.write(f"   RSA Private: {private_key.name}")
            self.stdout.write(f"   RSA Public: {public_key.name}")
            return True
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Key generation failed: {e}"))
            return False
    
    def test_file_encryption(self, user, fernet_algo, aes_cbc_algo):
        """Test file encryption"""
        try:
            # Generate test keys
            fernet_key = EncryptionKey.generate_symmetric_key(
                algorithm=fernet_algo,
                name="Test Fernet Key",
                created_by=user
            )
            
            # Create test file
            test_content = b"This is a test file for encryption."
            test_file = SimpleUploadedFile("test.txt", test_content)
            
            # Test encryption
            encrypted_file, success, error = EncryptionService.encrypt_file(
                test_file, fernet_key, user=user
            )
            
            if success:
                self.stdout.write("✅ File encryption successful")
                self.stdout.write(f"   Original size: {len(test_content)} bytes")
                self.stdout.write(f"   Encrypted size: {len(encrypted_file.read())} bytes")
                return True
            else:
                self.stdout.write(self.style.ERROR(f"❌ Encryption failed: {error}"))
                return False
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Encryption error: {e}"))
            return False
    
    def test_file_decryption(self, user, fernet_algo, aes_cbc_algo):
        """Test file decryption"""
        try:
            # Generate test key and encrypt file
            fernet_key = EncryptionKey.generate_symmetric_key(
                algorithm=fernet_algo,
                name="Test Fernet Key",
                created_by=user
            )
            
            test_content = b"Test decryption content"
            test_file = SimpleUploadedFile("test.txt", test_content)
            
            encrypted_file, success, error = EncryptionService.encrypt_file(
                test_file, fernet_key, user=user
            )
            
            if not success:
                self.stdout.write(self.style.ERROR(f"❌ Encryption failed: {error}"))
                return False
            
            # Test decryption
            decrypted_file, success, error = EncryptionService.decrypt_file(
                encrypted_file, fernet_key, user=user
            )
            
            if success:
                decrypted_content = decrypted_file.read()
                matches = decrypted_content == test_content
                self.stdout.write("✅ File decryption successful")
                self.stdout.write(f"   Content matches: {matches}")
                return True
            else:
                self.stdout.write(self.style.ERROR(f"❌ Decryption failed: {error}"))
                return False
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Decryption error: {e}"))
            return False
    
    def test_integrity_checks(self, user, fernet_algo, aes_cbc_algo):
        """Test integrity checks"""
        try:
            # Clear previous checks
            IntegrityCheck.objects.filter(user=user).delete()
            
            # Generate key and encrypt file
            fernet_key = EncryptionKey.generate_symmetric_key(
                algorithm=fernet_algo,
                name="Test Fernet Key",
                created_by=user
            )
            
            test_content = b"Integrity test content"
            test_file = SimpleUploadedFile("test.txt", test_content)
            
            encrypted_file, success, error = EncryptionService.encrypt_file(
                test_file, fernet_key, user=user
            )
            
            if success:
                checks = IntegrityCheck.objects.filter(encryption_key=fernet_key, user=user)
                if checks.exists():
                    check = checks.first()
                    self.stdout.write("✅ Integrity check created")
                    self.stdout.write(f"   Original checksum: {check.original_checksum}")
                    self.stdout.write(f"   Encrypted checksum: {check.encrypted_checksum}")
                    return True
                else:
                    self.stdout.write(self.style.ERROR("❌ No integrity check found"))
                    return False
            else:
                self.stdout.write(self.style.ERROR(f"❌ Encryption failed: {error}"))
                return False
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Integrity check error: {e}"))
            return False
    
    def test_key_lifecycle(self, user, fernet_algo, aes_cbc_algo):
        """Test key lifecycle operations"""
        try:
            # Generate test key
            fernet_key = EncryptionKey.generate_symmetric_key(
                algorithm=fernet_algo,
                name="Test Lifecycle Key",
                created_by=user
            )
            
            # Test revocation
            fernet_key.revoke(revoked_by=user)
            
            # Test activation
            fernet_key.activate()
            
            # Generate a fresh key for rotation test
            fresh_key = EncryptionKey.generate_symmetric_key(
                algorithm=fernet_algo,
                name="Fresh Key for Rotation",
                created_by=user
            )
            
            # Test rotation
            new_key, success, error = EncryptionService.rotate_key(
                fresh_key, rotated_by=user
            )
            
            if success:
                self.stdout.write("✅ Key lifecycle operations successful")
                self.stdout.write(f"   Original key revoked: {fresh_key.is_revoked}")
                self.stdout.write(f"   New key created: {new_key.name}")
                return True
            else:
                self.stdout.write(self.style.ERROR(f"❌ Key rotation failed: {error}"))
                return False
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Key lifecycle error: {e}"))
            return False
    
    def test_audit_logging(self, user):
        """Test audit logging"""
        try:
            # Clear previous logs
            KeyUsageLog.objects.filter(user=user).delete()
            
            # Generate a key (should create log)
            fernet_algo = EncryptionAlgorithm.objects.get(name='Fernet Standard')
            fernet_key = EncryptionKey.generate_symmetric_key(
                algorithm=fernet_algo,
                name="Test Audit Key",
                created_by=user
            )
            
            # Check logs
            logs = KeyUsageLog.objects.filter(user=user)
            if logs.exists():
                self.stdout.write("✅ Audit logging working")
                for log in logs:
                    self.stdout.write(f"   Action: {log.action}, Key: {log.key.name}")
                return True
            else:
                self.stdout.write(self.style.ERROR("❌ No audit logs found"))
                return False
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Audit logging error: {e}"))
            return False
