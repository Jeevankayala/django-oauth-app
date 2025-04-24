from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
import os

class Command(BaseCommand):
    help = 'Create a superuser non-interactively using environment variables for CustomUser'

    def handle(self, *args, **options):
        User = get_user_model()
        email = os.getenv('DJANGO_SUPERUSER_EMAIL')
        clerk_id = os.getenv('DJANGO_SUPERUSER_CLERK_ID')
        password = os.getenv('DJANGO_SUPERUSER_PASSWORD')

        if not email or not clerk_id or not password:
            self.stdout.write(self.style.ERROR('Missing required environment variables: DJANGO_SUPERUSER_EMAIL, DJANGO_SUPERUSER_CLERK_ID, DJANGO_SUPERUSER_PASSWORD'))
            return

        if User.objects.filter(email=email).exists() or User.objects.filter(clerk_id=clerk_id).exists():
            self.stdout.write(self.style.WARNING(f'Superuser with email {email} or clerk_id {clerk_id} already exists'))
            return

        try:
            User.objects.create_superuser(
                email=email,
                clerk_id=clerk_id,
                password=password,
                username=None,  # Optional, as username is nullable
                is_staff=True,
                is_superuser=True,
                role='org:admin',  # Optional: Align with Clerk metadata
                status='active'    # Optional: Align with Clerk metadata
            )
            self.stdout.write(self.style.SUCCESS(f'Superuser with email {email} created successfully'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Failed to create superuser: {str(e)}'))