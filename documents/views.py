from django.shortcuts import get_object_or_404, render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404
from django.views.decorators.http import require_POST
from .models import Document, DocumentVersion
from .forms import DocumentForm, DocumentReuploadForm
from encryption.models import EncryptionKey
from encryption.services import EncryptionService
from audit.models import AuditLog
import hashlib


def generate_checksum(file):
    checksum = hashlib.sha256()
    for chunk in file.chunks():
        checksum.update(chunk)
    file.seek(0)
    return checksum.hexdigest()


def document_list(request):
    # For now, show all documents or empty list if no user
    if request.user.is_authenticated:
        documents = Document.objects.filter(owner=request.user, is_deleted=False)
    else:
        documents = Document.objects.none()  # Empty queryset for anonymous users
    return render(request, 'documents/document_list.html', {'documents': documents})



def upload_document(request):
    if not request.user.is_authenticated:
        messages.error(request, 'Please log in to upload documents.')
        return redirect('document_list')
        
    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = form.cleaned_data['file']
            checksum = generate_checksum(uploaded_file)

            document = form.save(commit=False)
            document.owner = request.user
            
            # Get default encryption key for documents
            try:
                default_key = EncryptionKey.objects.filter(
                    key_type='symmetric',
                    is_active=True,
                    revoked_at__isnull=True
                ).first()
                
                # Check if the key is valid (not expired)
                if not default_key or not default_key.is_valid:
                    # Generate a default key if none exists
                    from encryption.models import EncryptionAlgorithm
                    fernet_algo = EncryptionAlgorithm.objects.filter(
                        mode='fernet'
                    ).first()
                    if fernet_algo:
                        default_key = EncryptionKey.generate_symmetric_key(
                            algorithm=fernet_algo,
                            name='Default Document Encryption Key',
                            created_by=request.user
                        )
                
                document.encryption_key = default_key
                print(f"Using encryption key: {default_key.name} (valid: {default_key.is_valid})")
            except Exception as e:
                messages.error(request, f'Error setting up encryption: {str(e)}')
                return render(request, 'documents/upload.html', {'form': form})
            
            document.save()

            # Encrypt the file
            try:
                encrypted_file, success, error_msg = document.encrypt_file_data(
                    uploaded_file, user=request.user
                )
                
                if not success:
                    messages.error(request, f'Encryption failed: {error_msg}')
                    document.delete()
                    return render(request, 'documents/upload.html', {'form': form})
                
                # Create document version
                version = DocumentVersion.objects.create(
                    document=document,
                    version_number=1,
                    encrypted_file=encrypted_file,
                    original_filename=uploaded_file.name,
                    checksum=checksum,
                    file_size=uploaded_file.size,
                )
                
                # Log the upload
                AuditLog.log_event(
                    user=request.user,
                    event_type='file_upload',
                    description=f"Uploaded document: {document.title}",
                    resource_type='document',
                    resource_id=str(document.pk),
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    session_key=request.session.session_key or ''
                )
                
                messages.success(request, 'Document uploaded and encrypted successfully!')
                return redirect('document_list')
                
            except Exception as e:
                messages.error(request, f'Error processing file: {str(e)}')
                document.delete()
                return render(request, 'documents/upload.html', {'form': form})
    else:
        form = DocumentForm()

    return render(request, 'documents/upload.html', {'form': form})


@login_required
@require_POST
def reupload_document(request, pk):
    """Re-upload a document with a new version"""
    document = get_object_or_404(Document, pk=pk, is_deleted=False)
    
    if document.owner != request.user:
        messages.error(request, 'You do not have permission to modify this document.')
        return redirect('document_list')
    
    form = DocumentReuploadForm(request.POST, request.FILES)
    if not form.is_valid() or 'file' not in request.FILES:
        messages.error(request, 'Please select a file to upload.')
        return redirect('document_list')
    
    uploaded_file = form.cleaned_data['file']
    checksum = generate_checksum(uploaded_file)
    
    # Update document details
    document.title = form.cleaned_data['title']
    document.description = form.cleaned_data['description']
    document.save()
    
    try:
        # Encrypt the new file
        encrypted_file, success, error_msg = document.encrypt_file_data(
            uploaded_file, user=request.user
        )
        
        if not success:
            messages.error(request, f'Encryption failed: {error_msg}')
            return redirect('document_list')
        
        # Get next version number
        latest_version = document.get_latest_version()
        next_version = (latest_version.version_number + 1) if latest_version else 1
        
        # Create new document version
        version = DocumentVersion.objects.create(
            document=document,
            version_number=next_version,
            encrypted_file=encrypted_file,
            original_filename=uploaded_file.name,
            checksum=checksum,
            file_size=uploaded_file.size,
        )
        
        # Log the re-upload
        AuditLog.log_event(
            user=request.user,
            event_type='file_upload',
            description=f"Re-uploaded document: {document.title} (Version {next_version})",
            resource_type='document',
            resource_id=str(document.pk),
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            session_key=request.session.session_key or ''
        )
        
        messages.success(request, f'Document re-uploaded successfully! New version: {next_version}')
        return redirect('document_list')
        
    except Exception as e:
        messages.error(request, f'Error processing file: {str(e)}')
        return redirect('document_list')


@login_required
@require_POST
def delete_document(request, pk):
    """Soft delete a document"""
    document = get_object_or_404(Document, pk=pk, is_deleted=False)
    
    if document.owner != request.user:
        messages.error(request, 'You do not have permission to delete this document.')
        return redirect('document_list')
    
    document.soft_delete()
    
    # Log the deletion
    AuditLog.log_event(
        user=request.user,
        event_type='file_delete',
        description=f"Deleted document: {document.title}",
        resource_type='document',
        resource_id=str(document.pk),
        ip_address=request.META.get('REMOTE_ADDR'),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        session_key=request.session.session_key or ''
    )
    
    messages.success(request, 'Document deleted successfully.')
    return redirect('document_list')


@login_required
def document_versions(request, pk):
    """Show all versions of a document"""
    document = get_object_or_404(Document, pk=pk, is_deleted=False)
    
    if document.owner != request.user:
        messages.error(request, 'You do not have permission to view this document.')
        return redirect('document_list')
    
    versions = document.versions.order_by('-version_number')
    
    return render(request, 'documents/document_versions.html', {
        'document': document,
        'versions': versions
    })


def download_document(request, pk):
    if not request.user.is_authenticated:
        messages.error(request, 'Please log in to download documents.')
        return redirect('document_list')
        
    document = get_object_or_404(Document, pk=pk, is_deleted=False)

    if document.owner != request.user:
        messages.error(request, 'You do not have permission to download this document.')
        return redirect('document_list')

    latest_version = document.get_latest_version()

    if not latest_version or not latest_version.encrypted_file:
        raise Http404("Document version not found")

    try:
        # Decrypt the file
        decrypted_file, success, error_msg = document.decrypt_file_data(
            latest_version.encrypted_file, user=request.user
        )
        
        if not success:
            messages.error(request, f'Decryption failed: {error_msg}')
            return redirect('document_list')
        
        # Log the download
        AuditLog.log_event(
            user=request.user,
            event_type='file_download',
            description=f"Downloaded document: {document.title}",
            resource_type='document',
            resource_id=str(document.pk),
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            session_key=request.session.session_key or ''
        )
        
        return FileResponse(
            decrypted_file.open("rb"),
            as_attachment=True,
            filename=latest_version.original_filename,
        )
        
    except Exception as e:
        messages.error(request, f'Error decrypting file: {str(e)}')
        return redirect('document_list')