from django import forms
from .models import AuditLog


class AuditLogFilterForm(forms.Form):
    """Form for filtering audit logs"""
    event_type = forms.ChoiceField(
        choices=[('', 'All Events')] + AuditLog.EVENT_TYPES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    user = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Search by username...'
        })
    )
    
    resource_type = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Search by resource type...'
        })
    )
    
    start_date = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )
    
    end_date = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )
    
    success = forms.ChoiceField(
        choices=[
            ('', 'All'),
            ('true', 'Success'),
            ('false', 'Failed')
        ],
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )


class CSVExportForm(forms.Form):
    """Form for CSV export of audit logs"""
    event_type = forms.ChoiceField(
        choices=[('', 'All Events')] + AuditLog.EVENT_TYPES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    user = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Search by username...'
        })
    )
    
    resource_type = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Search by resource type...'
        })
    )
    
    start_date = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )
    
    end_date = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )
    
    success = forms.ChoiceField(
        choices=[
            ('', 'All'),
            ('true', 'Success'),
            ('false', 'Failed')
        ],
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    
    max_records = forms.IntegerField(
        min_value=1,
        max_value=50000,
        initial=10000,
        required=False,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': 'Maximum records (default: 10000)'
        })
    )
