from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission, ContentType
from django.contrib.contenttypes.models import ContentType
from django.core.management.utils import get_default_username


class Command(BaseCommand):
    help = 'Set up audit permissions for staff users'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--group',
            type=str,
            default='audit_staff',
            help='Name of the permission group to create'
        )
    
    def handle(self, *args, **options):
        group_name = options['group']
        
        # Define audit permissions
        permissions = [
            ('view_auditlog', 'Can view audit logs'),
            ('export_auditlog', 'Can export audit logs'),
            ('delete_auditlog', 'Can delete audit logs'),
            ('change_auditlog', 'Can change audit logs'),
        ]
        
        # Get or create content type for audit logs
        audit_log_content_type, created = ContentType.objects.get_or_create(
            app_label='audit',
            model='auditlog'
        )
        
        created_permissions = []
        for codename, name in permissions:
            # Check if permission already exists
            try:
                permission = Permission.objects.get(
                    codename=codename,
                    content_type=audit_log_content_type
                )
                self.stdout.write(self.style.SUCCESS(f"✅ Permission '{name}' already exists"))
            except Permission.DoesNotExist:
                # Create new permission
                permission = Permission.objects.create(
                    codename=codename,
                    name=name,
                    content_type=audit_log_content_type
                )
                created_permissions.append(permission)
                self.stdout.write(self.style.SUCCESS(f"✅ Created permission '{name}'"))
        
        # Get or create permission group
        from django.contrib.auth.models import Group
        group, created = Group.objects.get_or_create(name=group_name)
        
        if created:
            # Add all permissions to the group
            for permission in created_permissions:
                group.permissions.add(permission)
                self.stdout.write(self.style.SUCCESS(f"✅ Added '{permission.name}' to group '{group_name}'"))
            
            self.stdout.write(self.style.SUCCESS(f"✅ Permission group '{group_name}' is ready"))
        else:
            self.stdout.write(self.style.WARNING(f"⚠️  Permission group '{group_name}' already exists"))
        
        # Display group members if needed
        if options['verbosity'] >= 2:
            self.stdout.write(f"\n📋 Group '{group_name}' members:")
            for user in group.user_set.all():
                self.stdout.write(f"   - {user.username}")
        
        # Display all permissions if needed
        if options['verbosity'] >= 2:
            self.stdout.write(f"\n🔐 All audit permissions:")
            for permission in Permission.objects.filter(content_type__app_label='audit'):
                self.stdout.write(f"   - {permission.codename}: {permission.name}")
