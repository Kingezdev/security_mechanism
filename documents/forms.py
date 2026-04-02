from django import forms
from django.utils import timezone
from .models import Document, DocumentShare


class DocumentForm(forms.ModelForm):
    file = forms.FileField(
        widget=forms.FileInput(attrs={'class': 'form-control'})
    )

    class Meta:
        model = Document
        fields = ['title', 'description', 'category']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control'}),
            'category': forms.Select(attrs={'class': 'form-select'}),
        }


class DocumentReuploadForm(forms.ModelForm):
    file = forms.FileField(
        widget=forms.FileInput(attrs={'class': 'form-control'}),
        help_text="Select a new file to replace the current version"
    )

    class Meta:
        model = Document
        fields = ['title', 'description']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control'}),
        }


class DocumentShareForm(forms.ModelForm):
    """Form for creating document shares"""
    
    expires_at = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={
            'class': 'form-control',
            'type': 'datetime-local'
        }),
        help_text="When should this share link expire? (leave blank for no expiry)"
    )
    
    max_downloads = forms.IntegerField(
        required=False,
        min_value=1,
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
        help_text="Maximum number of downloads allowed (leave blank for unlimited)"
    )

    class Meta:
        model = DocumentShare
        fields = ['permission', 'expires_at', 'max_downloads']
        widgets = {
            'permission': forms.Select(attrs={'class': 'form-select'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['permission'].choices = DocumentShare.PERMISSION_CHOICES
        
        # Set minimum datetime to now
        self.fields['expires_at'].widget.attrs['min'] = timezone.now().strftime('%Y-%m-%dT%H:%M')
    
    def clean_expires_at(self):
        expires_at = self.cleaned_data.get('expires_at')
        if expires_at and expires_at <= timezone.now():
            raise forms.ValidationError("Expiry time must be in the future.")
        return expires_at