from django.contrib import admin
from django.utils.html import format_html
from django.db.models import Count
from django.utils.safestring import mark_safe
from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = (
        'timestamp', 'user', 'event_type', 'event_description', 
        'resource_type', 'success', 'ip_address'
    )
    list_filter = (
        'event_type', 'user', 'resource_type', 'success', 'timestamp',
        'ip_address'
    )
    search_fields = (
        'user__username', 'event_description', 'resource_type', 
        'resource_id', 'ip_address', 'error_message'
    )
    readonly_fields = (
        'timestamp', 'id'
    )
    
    date_hierarchy = 'timestamp'
    ordering = ['-timestamp']
    
    fieldsets = (
        ('Event Information', {
            'fields': (
                'user', 'event_type', 'event_description', 'success'
            )
        }),
        ('Resource Details', {
            'fields': (
                'resource_type', 'resource_id', 'old_value', 'new_value'
            ),
            'classes': ('collapse',)
        }),
        ('Technical Details', {
            'fields': (
                'ip_address', 'user_agent', 'session_key', 'metadata'
            ),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        """Optimize queryset with select_related"""
        qs = super().get_queryset(request)
        return qs.select_related('user')
    
    def get_readonly_fields(self, request, obj=None):
        """Make timestamp and ID readonly"""
        readonly = list(self.readonly_fields)
        if obj and obj.pk:
            readonly.append('id')
        return readonly
    
    def has_add_permission(self, request):
        """Audit logs should not be manually added"""
        return request.user.is_superuser
    
    def has_change_permission(self, request, obj=None):
        """Audit logs should not be changed"""
        return request.user.is_superuser
    
    def has_delete_permission(self, request, obj=None):
        """Audit logs should not be deleted"""
        return request.user.is_superuser
    
    def get_actions(self, request):
        """Remove add/change/delete actions"""
        actions = super().get_actions(request)
        if 'delete_selected' in actions:
            del actions['delete_selected']
        return actions
    
    def changelist_view(self, request, extra_context=None):
        """Add summary statistics to changelist view"""
        response = super().changelist_view(request, extra_context)
        
        # Add summary statistics
        total_events = AuditLog.objects.count()
        today_events = AuditLog.objects.filter(
            timestamp__date=request.user.last_login
        ).count() if hasattr(request.user, 'last_login') else 0
        
        failed_events = AuditLog.objects.filter(success=False).count()
        security_events = AuditLog.objects.filter(
            event_type__in=['security_event', 'integrity_failure']
        ).count()
        
        summary_html = format_html(
            '<div class="audit-summary" style="margin: 10px 0; padding: 10px; '
            'background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 5px;">'
            '<h3>Audit Summary</h3>'
            '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px;">'
            '<div><strong>Total Events:</strong> {}</div>'
            '<div><strong>Today:</strong> {}</div>'
            '<div><strong>Failed:</strong> {}</div>'
            '<div><strong>Security Events:</strong> {}</div>'
            '</div>'
            '</div>',
            total_events, today_events, failed_events, security_events
        )
        
        response.context_data.update({
            'audit_summary': mark_safe(summary_html)
        })
        
        return response
