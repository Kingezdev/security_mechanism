from django.urls import path
from . import views

app_name = 'audit'

urlpatterns = [
    path('', views.audit_dashboard, name='audit_dashboard'),
    path('logs/', views.AuditLogListView.as_view(), name='audit_log_list'),
    path('log/<uuid:pk>/', views.AuditLogDetailView.as_view(), name='audit_log_detail'),
    path('export/', views.CSVExportView.as_view(), name='csv_export'),
]
