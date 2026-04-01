from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid


class AuditLog(models.Model):
    """Comprehensive audit logging model"""
    EVENT_TYPES = [
        ('login', 'User Login'),
        ('logout', 'User Logout'),
        ('file_access', 'File Access'),
        ('file_upload', 'File Upload'),
        ('file_download', 'File Download'),
        ('file_delete', 'File Delete'),
        ('permission_change', 'Permission Change'),
        ('user_create', 'User Created'),
        ('user_update', 'User Updated'),
        ('user_delete', 'User Deleted'),
        ('encryption_key_generate', 'Encryption Key Generated'),
        ('encryption_key_revoke', 'Encryption Key Revoked'),
        ('encryption_key_rotate', 'Encryption Key Rotated'),
        ('encryption_operation', 'Encryption Operation'),
        ('decryption_operation', 'Decryption Operation'),
        ('integrity_check', 'Integrity Check'),
        ('integrity_failure', 'Integrity Failure'),
        ('system_backup', 'System Backup'),
        ('system_restore', 'System Restore'),
        ('config_change', 'Configuration Change'),
        ('security_event', 'Security Event'),
        ('api_access', 'API Access'),
        ('data_export', 'Data Export'),
        ('data_import', 'Data Import'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, 
                           help_text="User who performed the action")
    event_type = models.CharField(max_length=50, choices=EVENT_TYPES, 
                                   help_text="Type of audit event")
    event_description = models.TextField(help_text="Detailed description of the event")
    resource_type = models.CharField(max_length=100, blank=True, 
                                    help_text="Type of resource affected (file, user, key, etc.)")
    resource_id = models.CharField(max_length=100, blank=True, 
                                 help_text="ID of the affected resource")
    old_value = models.TextField(blank=True, null=True, 
                             help_text="Previous value before the change")
    new_value = models.TextField(blank=True, null=True, 
                             help_text="New value after the change")
    ip_address = models.GenericIPAddressField(null=True, blank=True, 
                                      help_text="IP address of the user")
    user_agent = models.TextField(blank=True, 
                               help_text="User agent string")
    session_key = models.CharField(max_length=100, blank=True, 
                                  help_text="Session identifier")
    success = models.BooleanField(default=True, help_text="Whether the operation was successful")
    error_message = models.TextField(blank=True, null=True, 
                               help_text="Error message if operation failed")
    metadata = models.JSONField(default=dict, blank=True, 
                              help_text="Additional event metadata as JSON")
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = "Audit Log"
        verbose_name_plural = "Audit Logs"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['event_type', 'timestamp']),
            models.Index(fields=['resource_type', 'resource_id']),
            models.Index(fields=['timestamp']),
        ]
    
    def __str__(self):
        return f"{self.user.username if self.user else 'System'} - {self.get_event_type_display()} - {self.timestamp}"
    
    @classmethod
    def log_event(cls, user, event_type, description=None, resource_type=None, 
                  resource_id=None, old_value=None, new_value=None, 
                  ip_address=None, user_agent=None, session_key=None, 
                  success=True, error_message=None, metadata=None):
        """Utility function to log audit events"""
        return cls.objects.create(
            user=user,
            event_type=event_type,
            event_description=description or f"{event_type} event",
            resource_type=resource_type,
            resource_id=resource_id,
            old_value=old_value,
            new_value=new_value,
            ip_address=ip_address,
            user_agent=user_agent,
            session_key=session_key,
            success=success,
            error_message=error_message,
            metadata=metadata or {}
        )
    
    @classmethod
    def log_security_event(cls, user, description, severity='medium', 
                           ip_address=None, user_agent=None, metadata=None):
        """Log security-specific events"""
        return cls.log_event(
            user=user,
            event_type='security_event',
            description=f"[{severity.upper()}] {description}",
            resource_type='security',
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={**(metadata or {}), 'severity': severity}
        )
    
    @classmethod
    def get_events_for_user(cls, user, event_types=None, start_date=None, end_date=None):
        """Get filtered audit events for a user"""
        queryset = cls.objects.filter(user=user)
        
        if event_types:
            queryset = queryset.filter(event_type__in=event_types)
        
        if start_date:
            queryset = queryset.filter(timestamp__gte=start_date)
        
        if end_date:
            queryset = queryset.filter(timestamp__lte=end_date)
        
        return queryset.order_by('-timestamp')
    
    @classmethod
    def get_events_by_type(cls, event_type, start_date=None, end_date=None):
        """Get audit events by type"""
        queryset = cls.objects.filter(event_type=event_type)
        
        if start_date:
            queryset = queryset.filter(timestamp__gte=start_date)
        
        if end_date:
            queryset = queryset.filter(timestamp__lte=end_date)
        
        return queryset.order_by('-timestamp')
    
    @classmethod
    def export_to_csv(cls, queryset):
        """Export audit logs to CSV format"""
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Timestamp', 'User', 'Event Type', 'Description', 'Resource Type', 
            'Resource ID', 'IP Address', 'Success', 'Error Message'
        ])
        
        # Write data
        for log in queryset:
            writer.writerow([
                log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                log.user.username if log.user else 'System',
                log.get_event_type_display(),
                log.event_description,
                log.resource_type or '',
                log.resource_id or '',
                log.ip_address or '',
                log.success,
                log.error_message or ''
            ])
        
        return output.getvalue()
