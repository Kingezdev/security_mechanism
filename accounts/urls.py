from django.urls import path
from . import views

urlpatterns = [
    # Authentication URLs
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # User Profile URLs
    path('profile/', views.profile_view, name='profile'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    
    # Admin URLs
    path('admin/dashboard/', views.admin_dashboard_view, name='admin_dashboard'),
    path('admin/users/', views.admin_user_list_view, name='admin_user_list'),
    path('admin/users/<int:user_id>/', views.admin_user_detail_view, name='admin_user_detail'),
    path('admin/users/<int:user_id>/change-role/', views.admin_change_role_view, name='admin_change_role'),
]
