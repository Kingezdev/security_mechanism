from django import forms
from .models import Document


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