from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.views.generic import ListView, DetailView
from django.views.generic.edit import FormView
from django.http import HttpResponse, Http404
from django.urls import reverse_lazy
from django.utils import timezone
from django.db.models import Q
from django.contrib import messages
from .models import AuditLog
from .forms import AuditLogFilterForm, CSVExportForm
import csv
from io import StringIO


class AuditLogListView(LoginRequiredMixin, PermissionRequiredMixin, ListView):
    """List view for audit logs with filtering"""
    model = AuditLog
    template_name = 'audit/audit_log_list.html'
    context_object_name = 'audit_logs'
    paginate_by = 50
    permission_required = 'audit.view_auditlog'
    
    def get_queryset(self):
        """Get filtered queryset"""
        queryset = super().get_queryset()
        
        # Apply filters from GET parameters
        event_type = self.request.GET.get('event_type')
        user_filter = self.request.GET.get('user')
        resource_type = self.request.GET.get('resource_type')
        start_date = self.request.GET.get('start_date')
        end_date = self.request.GET.get('end_date')
        success_filter = self.request.GET.get('success')
        
        if event_type:
            queryset = queryset.filter(event_type=event_type)
        
        if user_filter:
            queryset = queryset.filter(user__username__icontains=user_filter)
        
        if resource_type:
            queryset = queryset.filter(resource_type__icontains=resource_type)
        
        if start_date:
            try:
                start_date = timezone.datetime.strptime(start_date, '%Y-%m-%d').date()
                queryset = queryset.filter(timestamp__date__gte=start_date)
            except ValueError:
                pass
        
        if end_date:
            try:
                end_date = timezone.datetime.strptime(end_date, '%Y-%m-%d').date()
                queryset = queryset.filter(timestamp__date__lte=end_date)
            except ValueError:
                pass
        
        if success_filter:
            queryset = queryset.filter(success=success_filter.lower() == 'true')
        
        return queryset.select_related('user')
    
    def get_context_data(self, **kwargs):
        """Add filter form and event type choices to context"""
        context = super().get_context_data(**kwargs)
        
        # Add filter form
        if 'filter_form' not in context:
            context['filter_form'] = AuditLogFilterForm(self.request.GET)
        
        # Add export form
        context['export_form'] = CSVExportForm()
        
        # Add event type choices for template
        context['event_types'] = AuditLog.EVENT_TYPES
        
        return context


class AuditLogDetailView(LoginRequiredMixin, PermissionRequiredMixin, DetailView):
    """Detail view for individual audit log"""
    model = AuditLog
    template_name = 'audit/audit_log_detail.html'
    context_object_name = 'audit_log'
    permission_required = 'audit.view_auditlog'
    
    def get_queryset(self):
        """Optimize with select_related"""
        return super().get_queryset().select_related('user')


class CSVExportView(LoginRequiredMixin, PermissionRequiredMixin, FormView):
    """CSV export view for audit logs"""
    form_class = CSVExportForm
    template_name = 'audit/csv_export.html'
    permission_required = 'audit.export_auditlog'
    success_url = reverse_lazy('audit:audit_log_list')
    
    def form_valid(self, form):
        """Handle CSV export"""
        cleaned_data = form.cleaned_data
        
        # Get base queryset
        queryset = AuditLog.objects.all()
        
        # Apply same filters as list view
        event_type = cleaned_data.get('event_type')
        user_filter = cleaned_data.get('user')
        resource_type = cleaned_data.get('resource_type')
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')
        success_filter = cleaned_data.get('success')
        
        if event_type:
            queryset = queryset.filter(event_type=event_type)
        
        if user_filter:
            queryset = queryset.filter(user__username__icontains=user_filter)
        
        if resource_type:
            queryset = queryset.filter(resource_type__icontains=resource_type)
        
        if start_date:
            try:
                start_date = timezone.datetime.strptime(start_date, '%Y-%m-%d').date()
                queryset = queryset.filter(timestamp__date__gte=start_date)
            except ValueError:
                messages.error(self.request, 'Invalid start date format')
                return self.form_invalid(form)
        
        if end_date:
            try:
                end_date = timezone.datetime.strptime(end_date, '%Y-%m-%d').date()
                queryset = queryset.filter(timestamp__date__lte=end_date)
            except ValueError:
                messages.error(self.request, 'Invalid end date format')
                return self.form_invalid(form)
        
        if success_filter:
            queryset = queryset.filter(success=success_filter.lower() == 'true')
        
        # Limit to reasonable number for export
        max_records = cleaned_data.get('max_records', 10000)
        queryset = queryset[:max_records]
        
        # Generate CSV
        csv_content = AuditLog.export_to_csv(queryset)
        
        # Create response
        response = HttpResponse(
            csv_content,
            content_type='text/csv',
            headers={'Content-Disposition': f'attachment; filename="audit_logs_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'}
        )
        
        messages.success(
            self.request, 
            f'Successfully exported {queryset.count()} audit log records'
        )
        
        return response


@login_required
@permission_required('audit.view_auditlog')
def audit_dashboard(request):
    """Dashboard view for audit statistics"""
    # Get summary statistics
    total_events = AuditLog.objects.count()
    
    # Event type statistics
    event_stats = []
    for event_type, display_name in AuditLog.EVENT_TYPES:
        count = AuditLog.objects.filter(event_type=event_type).count()
        event_stats.append({
            'type': event_type,
            'display_name': display_name,
            'count': count,
            'percentage': (count / total_events * 100) if total_events > 0 else 0
        })
    
    # Recent events
    recent_events = AuditLog.objects.select_related('user').order_by('-timestamp')[:20]
    
    # Security events (high priority)
    security_events = AuditLog.objects.filter(
        event_type__in=['security_event', 'integrity_failure']
    ).order_by('-timestamp')[:10]
    
    # Failed events
    failed_events = AuditLog.objects.filter(success=False).order_by('-timestamp')[:10]
    
    context = {
        'total_events': total_events,
        'event_stats': event_stats,
        'recent_events': recent_events,
        'security_events': security_events,
        'failed_events': failed_events,
    }
    
    return render(request, 'audit/audit_dashboard.html', context)
