from django.shortcuts import get_object_or_404, render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404
from .models import Document, DocumentVersion
from .forms import DocumentForm
import hashlib


def generate_checksum(file):
    checksum = hashlib.sha256()
    for chunk in file.chunks():
        checksum.update(chunk)
    file.seek(0)
    return checksum.hexdigest()


@login_required
def upload_document(request):
    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = form.cleaned_data['file']
            checksum = generate_checksum(uploaded_file)

            document = form.save(commit=False)
            document.owner = request.user
            document.save()

            DocumentVersion.objects.create(
                document=document,
                version_number=1,
                encrypted_file=uploaded_file,
                original_filename=uploaded_file.name,
                checksum=checksum,
                file_size=uploaded_file.size,
            )

            messages.success(request, 'Document uploaded successfully!')
            return redirect('document_list')
    else:
        form = DocumentForm()

    return render(request, 'documents/upload.html', {'form': form})


@login_required
def download_document(request, pk):
    document = get_object_or_404(Document, pk=pk, is_deleted=False)

    if document.owner != request.user:
        messages.error(request, 'You do not have permission to download this document.')
        return redirect('document_list')

    latest_version = document.versions.order_by('-version_number').first()

    if not latest_version or not latest_version.encrypted_file:
        raise Http404("Document version not found")

    return FileResponse(
        latest_version.encrypted_file.open("rb"),
        as_attachment=True,
        filename=latest_version.original_filename,
    )

    # TODO: Add document reupload and versioning functionality