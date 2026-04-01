from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import User
from django.db.models import Count, Q
from django.http import JsonResponse
from django.core.paginator import Paginator
from .models import UserProfile
from .forms import CustomUserCreationForm, CustomAuthenticationForm, UserUpdateForm, ProfileUpdateForm

def admin_required(view_func):
    """Decorator to require admin access"""
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        if not hasattr(request.user, 'profile') or request.user.profile.role != 'admin':
            messages.error(request, 'You do not have permission to access this page.')
            return redirect('dashboard')
        return view_func(request, *args, **kwargs)
    return wrapper

def register_view(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f'Account created successfully for {username}! You can now log in.')
            return redirect('login')
    else:
        form = CustomUserCreationForm()
    
    return render(request, 'accounts/register.html', {'form': form})


def login_view(request):
    if request.user.is_authenticated:
        return redirect('document_list')
        
    if request.method == 'POST':
        form = CustomAuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, f'Welcome back, {user.get_full_name() or username}!')
                next_url = request.GET.get('next', 'document_list')
                return redirect(next_url)
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Invalid username or password.')
    else:
        form = CustomAuthenticationForm()
    
    return render(request, 'accounts/login.html', {'form': form})


@login_required
def logout_view(request):
    username = request.user.username
    logout(request)
    messages.success(request, f'You have been logged out, {username}.')
    return redirect('login')


@login_required
def profile_view(request):
    profile = get_object_or_404(UserProfile, user=request.user)
    
    if request.method == 'POST':
        user_form = UserUpdateForm(request.POST, instance=request.user)
        profile_form = ProfileUpdateForm(request.POST, instance=profile)
        
        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, 'Your profile has been updated successfully!')
            return redirect('profile')
    else:
        user_form = UserUpdateForm(instance=request.user)
        profile_form = ProfileUpdateForm(instance=profile)
    
    context = {
        'user_form': user_form,
        'profile_form': profile_form,
        'profile': profile
    }
    
    return render(request, 'accounts/profile.html', context)


@login_required
def dashboard_view(request):
    profile = request.user.profile
    
    # Get dashboard data based on user role
    context = {
        'profile': profile,
        'total_documents': request.user.documents.filter(is_deleted=False).count(),
        'recent_documents': request.user.documents.filter(is_deleted=False).order_by('-created_at')[:5],
    }
    
    return render(request, 'accounts/dashboard.html', context)


@admin_required
def admin_dashboard_view(request):
    """Admin dashboard with system statistics"""
    
    # System statistics
    total_users = User.objects.count()
    total_documents = 0  # Will be updated when documents app is available
    total_events = 0  # Will be updated when events are implemented
    
    # User statistics by role
    role_stats = UserProfile.objects.values('role').annotate(count=Count('role')).order_by('role')
    
    # Department statistics
    dept_stats = UserProfile.objects.values('department').annotate(count=Count('department')).order_by('-count')[:5]
    
    # Recent users
    recent_users = User.objects.select_related('profile').order_by('-date_joined')[:5]
    
    # Active users (users who logged in recently)
    from django.utils import timezone
    from datetime import timedelta
    thirty_days_ago = timezone.now() - timedelta(days=30)
    active_users = User.objects.filter(last_login__gte=thirty_days_ago).count()
    
    context = {
        'total_users': total_users,
        'total_documents': total_documents,
        'total_events': total_events,
        'active_users': active_users,
        'role_stats': role_stats,
        'dept_stats': dept_stats,
        'recent_users': recent_users,
    }
    
    return render(request, 'accounts/admin/dashboard.html', context)


@admin_required
def admin_user_list_view(request):
    """Admin user list with search and filtering"""
    
    search_query = request.GET.get('search', '')
    role_filter = request.GET.get('role', '')
    department_filter = request.GET.get('department', '')
    
    users = User.objects.select_related('profile').all()
    
    # Apply filters
    if search_query:
        users = users.filter(
            Q(username__icontains=search_query) |
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query) |
            Q(email__icontains=search_query) |
            Q(profile__identification_number__icontains=search_query)
        )
    
    if role_filter:
        users = users.filter(profile__role=role_filter)
    
    if department_filter:
        users = users.filter(profile__department__icontains=department_filter)
    
    # Pagination
    paginator = Paginator(users, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get available roles and departments for filters
    roles = UserProfile.ROLE_CHOICES
    departments = UserProfile.objects.values_list('department', flat=True).distinct()
    departments = [dept for dept in departments if dept]
    
    context = {
        'page_obj': page_obj,
        'search_query': search_query,
        'role_filter': role_filter,
        'department_filter': department_filter,
        'roles': roles,
        'departments': departments,
    }
    
    return render(request, 'accounts/admin/user_list.html', context)


@admin_required
def admin_change_role_view(request, user_id):
    """Change user role"""
    
    user = get_object_or_404(User, id=user_id)
    profile = user.profile
    
    if request.method == 'POST':
        new_role = request.POST.get('role')
        if new_role in [choice[0] for choice in UserProfile.ROLE_CHOICES]:
            old_role = profile.get_role_display()
            profile.role = new_role
            profile.save()
            
            messages.success(
                request, 
                f'Successfully changed {user.username}\'s role from {old_role} to {profile.get_role_display()}'
            )
        else:
            messages.error(request, 'Invalid role selected.')
        
        return redirect('admin_user_list')
    
    context = {
        'target_user': user,
        'current_role': profile.role,
        'roles': UserProfile.ROLE_CHOICES,
    }
    
    return render(request, 'accounts/admin/change_role.html', context)


@admin_required
def admin_user_detail_view(request, user_id):
    """Detailed view of a user"""
    
    user = get_object_or_404(User, id=user_id)
    profile = user.profile
    
    # Get user's documents (when documents app is available)
    user_documents = []  # Will be updated when documents app is available
    
    context = {
        'target_user': user,
        'profile': profile,
        'user_documents': user_documents,
    }
    
    return render(request, 'accounts/admin/user_detail.html', context)