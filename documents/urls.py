from django.urls import path
from . import views

urlpatterns = [
    path('', views.document_list, name='document_list'),
    path('upload/', views.upload_document, name='upload_document'),
    path('download/<int:pk>/', views.download_document, name='download_document'),
    path('reupload/<int:pk>/', views.reupload_document, name='reupload_document'),
    path('delete/<int:pk>/', views.delete_document, name='delete_document'),
    path('versions/<int:pk>/', views.document_versions, name='document_versions'),
]