from django.core.management.base import BaseCommand
from django.core.exceptions import ImproperlyConfigured
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from authentication.models import GoogleToken
from input_data_management.models import GoogleDriveWebhook  # Replace with your app's models path
from input_data_management.utils import get_meet_folder_id  # Replace with your app's utils path
import uuid
import logging
from django.conf import settings
from authentication.utils import refresh_oauth_token

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = "Set up Google Drive webhooks for all users with Google tokens"

    def handle(self, *args, **kwargs):
        # Validate WEBHOOK_URL
        if not hasattr(settings, 'WEBHOOK_URL'):
            raise ImproperlyConfigured("WEBHOOK_URL is not defined in settings.py")
        if not settings.WEBHOOK_URL.startswith("https"):
            raise ImproperlyConfigured("WEBHOOK_URL must use HTTPS")

        # Get all users with Google tokens
        google_tokens = GoogleToken.objects.all()
        if not google_tokens:
            logger.warning("No Google tokens found. No webhooks will be set up.")
            self.stdout.write(self.style.WARNING("No Google tokens found."))
            return

        for token in google_tokens:
            try:
                user = token.user
                logger.info(f"Setting up webhook for user {user.id}")

                # Use refresh_oauth_token to get OAuth2Session
                oauth = refresh_oauth_token(
                    token,
                    'https://oauth2.googleapis.com/token',
                    settings.GOOGLE_CLIENT_ID,
                    settings.GOOGLE_CLIENT_SECRET
                )

                # Get Meet Recordings folder ID
                folder_id = get_meet_folder_id(oauth, user.id)
                if not folder_id:
                    logger.error(f"Meet Recordings folder not found for user {user.id}")
                    self.stdout.write(self.style.ERROR(f"Failed to find Meet Recordings folder for user {user.id}"))
                    continue

                # Check if webhook already exists
                if GoogleDriveWebhook.objects.filter(user=user).exists():
                    logger.info(f"Webhook already exists for user {user.id}. Skipping.")
                    self.stdout.write(self.style.SUCCESS(f"Webhook already exists for user {user.id}"))
                    continue

                # Create unique channel ID and token
                channel_id = str(uuid.uuid4())
                channel_token = str(uuid.uuid4())

                # Register webhook using OAuth2Session
                webhook_url = 'https://www.googleapis.com/drive/v3/changes/watch?pageToken=1'
                headers = {'Content-Type': 'application/json'}
                body = {
                    'id': channel_id,
                    'type': 'web_hook',
                    'address': settings.WEBHOOK_URL,
                    'token': channel_token,
                    'resourceUri': f'https://www.googleapis.com/drive/v3/files/{folder_id}'
                }
                response = oauth.post(webhook_url, json=body, headers=headers)
                if response.status_code != 200:
                    logger.error(f"Failed to register webhook: {response.text}")
                    raise Exception(f"Webhook registration failed: {response.text}")

                response_data = response.json()

                # Store webhook details
                GoogleDriveWebhook.objects.create(
                    user=user,
                    channel_id=channel_id,
                    resource_id=response_data['resourceId'],
                    channel_token=channel_token,
                    last_page_token='1'
                )
                logger.info(f"Successfully set up webhook for user {user.id}, channel_id={channel_id}")
                self.stdout.write(self.style.SUCCESS(f"Webhook set up for user {user.id}"))

            except Exception as e:
                logger.error(f"Error setting up webhook for user {user.id}: {str(e)}", exc_info=True)
                self.stdout.write(self.style.ERROR(f"Failed to set up webhook for user {user.id}: {str(e)}"))

        self.stdout.write(self.style.SUCCESS("Webhook setup completed."))