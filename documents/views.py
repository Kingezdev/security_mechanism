from django.shortcuts import get_object_or_404, render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404
from django.views.decorators.http import require_POST
from django.contrib.auth import get_user_model
from .models import Document, DocumentVersion, DocumentShare
from .forms import DocumentForm, DocumentReuploadForm, DocumentShareForm
from encryption.models import EncryptionKey
from encryption.services import EncryptionService
from audit.models import AuditLog
import hashlib

User = get_user_model()


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


@login_required
def share_document(request, pk):
    """Share a document with secure token"""
    document = get_object_or_404(Document, pk=pk, is_deleted=False)
    
    if document.owner != request.user:
        messages.error(request, 'You do not have permission to share this document.')
        return redirect('document_list')
    
    if request.method == 'POST':
        form = DocumentShareForm(request.POST)
        if form.is_valid():
            share = DocumentShare.create_share(
                document=document,
                shared_by=request.user,
                permission=form.cleaned_data['permission'],
                expires_at=form.cleaned_data['expires_at'],
                max_downloads=form.cleaned_data['max_downloads']
            )
            
            # Log the sharing
            AuditLog.log_event(
                user=request.user,
                event_type='file_share',
                description=f"Shared document: {document.title} ({share.get_permission_display()})",
                resource_type='document',
                resource_id=str(document.pk),
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                session_key=request.session.session_key or '',
                metadata={
                    'share_id': str(share.id),
                    'share_token': share.share_token,
                    'permission': share.permission,
                    'expires_at': share.expires_at.isoformat() if share.expires_at else None,
                    'max_downloads': share.max_downloads
                }
            )
            
            share_url = share.get_share_url(request)
            messages.success(request, f'Document shared successfully! Share URL: {share_url}')
            return redirect('document_list')
    else:
        form = DocumentShareForm()
    
    return render(request, 'documents/share_document.html', {
        'document': document,
        'form': form
    })


@login_required
def manage_shares(request, pk):
    """Manage existing shares for a document"""
    document = get_object_or_404(Document, pk=pk, is_deleted=False)
    
    if document.owner != request.user:
        messages.error(request, 'You do not have permission to manage shares for this document.')
        return redirect('document_list')
    
    shares = document.shares.all().order_by('-created_at')
    
    return render(request, 'documents/manage_shares.html', {
        'document': document,
        'shares': shares
    })


@login_required
@require_POST
def revoke_share(request, share_id):
    """Revoke a document share"""
    share = get_object_or_404(DocumentShare, id=share_id)
    
    if share.document.owner != request.user:
        messages.error(request, 'You do not have permission to revoke this share.')
        return redirect('document_list')
    
    share.revoke()
    
    # Log the revocation
    AuditLog.log_event(
        user=request.user,
        event_type='file_share_revoke',
        description=f"Revoked share for document: {share.document.title}",
        resource_type='document',
        resource_id=str(share.document.pk),
        ip_address=request.META.get('REMOTE_ADDR'),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        session_key=request.session.session_key or '',
        metadata={
            'share_id': str(share.id),
            'share_token': share.share_token
        }
    )
    
    messages.success(request, 'Share link revoked successfully.')
    return redirect('manage_shares', pk=share.document.pk)


def shared_document_view(request, token):
    """View a shared document via secure token"""
    share = get_object_or_404(DocumentShare, share_token=token)
    
    # Check if share is valid
    is_valid, message = share.is_valid()
    if not is_valid:
        return render(request, 'documents/share_error.html', {
            'error': message,
            'share': share
        })
    
    return render(request, 'documents/shared_document.html', {
        'share': share,
        'document': share.document
    })


def shared_document_download(request, token):
    """Download a shared document via secure token"""
    share = get_object_or_404(DocumentShare, share_token=token)
    
    # Check if share is valid
    is_valid, message = share.is_valid()
    if not is_valid:
        messages.error(request, message)
        return redirect('shared_document_view', token=token)
    
    # Check if download is allowed
    can_download, message = share.can_download()
    if not can_download:
        messages.error(request, message)
        return redirect('shared_document_view', token=token)
    
    latest_version = share.document.get_latest_version()
    if not latest_version or not latest_version.encrypted_file:
        raise Http404("Document version not found")
    
    try:
        # Decrypt the file
        decrypted_file, success, error_msg = share.document.decrypt_file_data(
            latest_version.encrypted_file
        )
        
        if not success:
            messages.error(request, f'Decryption failed: {error_msg}')
            return redirect('shared_document_view', token=token)
        
        # Increment download count
        share.increment_download_count()
        
        # Log the download
        AuditLog.log_event(
            user=None,  # Anonymous download
            event_type='file_download',
            description=f"Downloaded shared document: {share.document.title}",
            resource_type='document',
            resource_id=str(share.document.pk),
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            session_key=request.session.session_key or '',
            metadata={
                'share_id': str(share.id),
                'share_token': share.share_token,
                'download_count': share.download_count
            }
        )
        
        return FileResponse(
            decrypted_file.open("rb"),
            as_attachment=True,
            filename=latest_version.original_filename,
        )
        
    except Exception as e:
        messages.error(request, f'Error decrypting file: {str(e)}')
        return redirect('shared_document_view', token=token)