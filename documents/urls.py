from django.urls import path
from . import views

urlpatterns = [
    path('', views.document_list, name='document_list'),
    path('upload/', views.upload_document, name='upload_document'),
    path('download/<int:pk>/', views.download_document, name='download_document'),
    path('reupload/<int:pk>/', views.reupload_document, name='reupload_document'),
    path('delete/<int:pk>/', views.delete_document, name='delete_document'),
    path('versions/<int:pk>/', views.document_versions, name='document_versions'),
    path('share/<int:pk>/', views.share_document, name='share_document'),
    path('manage-shares/<int:pk>/', views.manage_shares, name='manage_shares'),
    path('revoke-share/<uuid:share_id>/', views.revoke_share, name='revoke_share'),
    path('shared/<str:token>/', views.shared_document_view, name='shared_document_view'),
    path('shared/<str:token>/download/', views.shared_document_download, name='shared_document_download'),
]