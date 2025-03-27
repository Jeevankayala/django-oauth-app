from django.shortcuts import redirect
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from requests_oauthlib import OAuth2Session
from django.conf import settings
from django.utils import timezone
from .models import *
import json
from datetime import datetime
import pytz
from django.contrib.auth.models import User
import logging
logger = logging.getLogger(__name__)

# OAuth Config
GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_CALENDAR_API = 'https://www.googleapis.com/calendar/v3/calendars/primary/events'
REDIRECT_URI = 'http://localhost:8000/api/auth/google/callback/'
GOOGLE_SCOPES = ['https://www.googleapis.com/auth/calendar.readonly','https://www.googleapis.com/auth/meetings.space.created','https://www.googleapis.com/auth/meetings.space.readonly']

class GoogleAuthView(APIView):
    def get(self, request):
        oauth = OAuth2Session(
            settings.GOOGLE_CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            scope=GOOGLE_SCOPES
        )
        authorization_url, state = oauth.authorization_url(GOOGLE_AUTH_URL)
        request.session['oauth_state'] = state
        request.session['next'] = request.GET.get('next', '/api/auth/google/callback/')
        return redirect(authorization_url)

class GoogleCallbackView(APIView):
    def get(self, request):
        if 'code' not in request.GET:
            return Response({'error': 'No authorization code provided'}, status=400)

        oauth = OAuth2Session(
            settings.GOOGLE_CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            state=request.session.get('oauth_state')
        )
        try:
            token = oauth.fetch_token(
                GOOGLE_TOKEN_URL,
                code=request.GET.get('code'),
                client_secret=settings.GOOGLE_CLIENT_SECRET
            )
        except Exception as e:
            return Response({'error': f'Token exchange failed: {str(e)}'}, status=400)

        # Create a test user if not logged in (for simplicity; use real auth in production)
        user, _ = User.objects.get_or_create(username='testuser')
        
        # Store the token
        expires_at = timezone.now() + timezone.timedelta(seconds=token['expires_in'])
        GoogleToken.objects.update_or_create(
            user=user,
            defaults={
                'access_token': token['access_token'],
                'refresh_token': token.get('refresh_token'),
                'expires_at': expires_at
            }
        )

        # Test the token (optional for now)
        oauth = OAuth2Session(settings.GOOGLE_CLIENT_ID, token=token)
        events = oauth.get(GOOGLE_CALENDAR_API).json()
        return Response({'message': 'Token stored successfully!', 'events': events.get('items', [])})
    
class GetCalendarEventsView(APIView):
    # permission_classes = [IsAuthenticated]  # Add auth in production

    def get(self, request):
        try:
            # Hardcode testuser for now (replace with real auth later)
            user = User.objects.get(username='testuser')
            token_obj = GoogleToken.objects.get(user=user)  # Replace with real user in production
            token = {
                'access_token': token_obj.access_token,
                'refresh_token': token_obj.refresh_token,
                'expires_at': token_obj.expires_at.isoformat()
            }

            expires_at = datetime.fromisoformat(token['expires_at'].replace('Z', '+00:00'))
            expires_at = pytz.UTC.localize(expires_at)  # Ensure UTC timezone
            
            oauth = OAuth2Session(settings.GOOGLE_CLIENT_ID, token=token)
            # Refresh token if expired
            if timezone.now() > expires_at:
                new_token = oauth.refresh_token(
                    GOOGLE_TOKEN_URL,
                    client_id=settings.GOOGLE_CLIENT_ID,
                    client_secret=settings.GOOGLE_CLIENT_SECRET
                )
                token_obj.access_token = new_token['access_token']
                token_obj.refresh_token = new_token.get('refresh_token', token_obj.refresh_token)
                token_obj.expires_at = timezone.now() + timezone.timedelta(seconds=new_token['expires_in'])
                token_obj.save()
                oauth = OAuth2Session(settings.GOOGLE_CLIENT_ID, token=new_token)

            events = oauth.get(GOOGLE_CALENDAR_API).json()
            return Response({'events': events.get('items', [])})
        except GoogleToken.DoesNotExist:
            return Response({'error': 'No token found. Please authenticate.'}, status=400)
        

class GetGoogleTokenView(APIView):
    def get(self, request):
        try:
            user = User.objects.get(username='testuser')  # Replace with real auth
            token_obj = GoogleToken.objects.get(user=user)
            token_data = {
                'access_token': token_obj.access_token,
                'refresh_token': token_obj.refresh_token,
                'expires_at': token_obj.expires_at.isoformat()
            }
            return Response(token_data)
        except GoogleToken.DoesNotExist:
            return Response({'error': 'No token found'}, status=400)


# Zoom OAuth Config
ZOOM_AUTH_URL = 'https://zoom.us/oauth/authorize'
ZOOM_TOKEN_URL = 'https://zoom.us/oauth/token'
ZOOM_API = 'https://api.zoom.us/v2/users/me'
ZOOM_REDIRECT_URI = 'http://localhost:8000/api/auth/zoom/callback/'
# ZOOM_SCOPES = ['meeting:read:meeting', 'meeting:read:summary', 'meeting:read:meeting_transcript', 'user:read:user', 'meeting:read:meeting_audio']
ZOOM_SCOPES = ['user:read:user']

class ZoomAuthView(APIView):
    def get(self, request):
        oauth = OAuth2Session(
            settings.ZOOM_CLIENT_ID,
            redirect_uri=ZOOM_REDIRECT_URI,
            scope=ZOOM_SCOPES
        )
        authorization_url, state = oauth.authorization_url(ZOOM_AUTH_URL)
        request.session['zoom_oauth_state'] = state
        request.session['next'] = request.GET.get('next', '/api/auth/zoom/callback/')
        return redirect(authorization_url)

class ZoomCallbackView(APIView):
    def get(self, request):
        if 'code' not in request.GET:
            return Response({'error': 'No authorization code provided'}, status=400)

        oauth = OAuth2Session(
            settings.ZOOM_CLIENT_ID,
            redirect_uri=ZOOM_REDIRECT_URI,
            state=request.session.get('zoom_oauth_state')
        )
        try:
            token = oauth.fetch_token(
                ZOOM_TOKEN_URL,
                code=request.GET.get('code'),
                client_secret=settings.ZOOM_CLIENT_SECRET,
                include_client_id=True  # Zoom requires client_id in token request
            )
        except Exception as e:
            return Response({'error': f'Token exchange failed: {str(e)}'}, status=400)

        # Create a test user if not logged in (for simplicity; use real auth in production)
        user, _ = User.objects.get_or_create(username='testuser')

        # Store the token
        expires_at = timezone.now() + timezone.timedelta(seconds=token['expires_in'])
        ZoomToken.objects.update_or_create(
            user=user,
            defaults={
                'access_token': token['access_token'],
                'refresh_token': token.get('refresh_token'),
                'expires_at': expires_at
            }
        )

        # Test the token by fetching user profile (optional)
        oauth = OAuth2Session(settings.ZOOM_CLIENT_ID, token=token)
        user_profile = oauth.get(ZOOM_API).json()
        return Response({'message': 'Zoom token stored successfully!', 'user_profile': user_profile})


# OAuth Config for Microsoft Teams
TEAMS_AUTH_URL = f'https://login.microsoftonline.com/{settings.TEAMS_TENANT_ID}/oauth2/v2.0/authorize'
TEAMS_TOKEN_URL = f'https://login.microsoftonline.com/{settings.TEAMS_TENANT_ID}/oauth2/v2.0/token'
TEAMS_CALENDAR_API = 'https://graph.microsoft.com/v1.0/me/events'
TEAMS_MEETINGS_API = 'https://graph.microsoft.com/v1.0/me/onlineMeetings'
TEAMS_REDIRECT_URI = 'http://localhost:8000/api/auth/teams/callback/'
TEAMS_SCOPES = [
    'https://graph.microsoft.com/User.Read',
    'https://graph.microsoft.com/Calendars.Read',
    'https://graph.microsoft.com/OnlineMeetings.ReadWrite'
]

class TeamsAuthView(APIView):
    def get(self, request):
        oauth = OAuth2Session(
            settings.TEAMS_CLIENT_ID,
            redirect_uri=TEAMS_REDIRECT_URI,
            scope=TEAMS_SCOPES
        )
        authorization_url, state = oauth.authorization_url(TEAMS_AUTH_URL)
        request.session['oauth_state'] = state
        request.session['next'] = request.GET.get('next', '/api/auth/teams/callback/')
        return redirect(authorization_url)

class TeamsCallbackView(APIView):
    def get(self, request):
        if 'code' not in request.GET:
            return Response({'error': 'No authorization code provided'}, status=400)

        oauth = OAuth2Session(
            settings.TEAMS_CLIENT_ID,
            redirect_uri=TEAMS_REDIRECT_URI,
            state=request.session.get('oauth_state')
        )
        try:
            token = oauth.fetch_token(
                TEAMS_TOKEN_URL,
                code=request.GET.get('code'),
                client_secret=settings.TEAMS_CLIENT_SECRET
            )
        except Exception as e:
            return Response({'error': f'Token exchange failed: {str(e)}'}, status=400)

        # Create a test user (replace with real auth in production)
        user, _ = User.objects.get_or_create(username='testuser')

        # Store the token
        expires_at = timezone.now() + timezone.timedelta(seconds=token['expires_in'])
        TeamsToken.objects.update_or_create(
            user=user,
            defaults={
                'access_token': token['access_token'],
                'refresh_token': token.get('refresh_token'),
                'expires_at': expires_at
            }
        )

        # Test the token (optional)
        oauth = OAuth2Session(settings.TEAMS_CLIENT_ID, token=token)
        events = oauth.get(TEAMS_CALENDAR_API).json()
        return Response({'message': 'Token stored successfully!', 'events': events.get('value', [])})

class GetTeamsCalendarEventsView(APIView):
    def get(self, request):
        try:
            user = User.objects.get(username='testuser')  # Replace with real auth
            token_obj = TeamsToken.objects.get(user=user)
            token = {
                'access_token': token_obj.access_token,
                'refresh_token': token_obj.refresh_token,
                'expires_at': token_obj.expires_at.isoformat()
            }

            expires_at = datetime.fromisoformat(token['expires_at'].replace('Z', '+00:00'))
            expires_at = pytz.UTC.localize(expires_at)

            oauth = OAuth2Session(settings.TEAMS_CLIENT_ID, token=token)
            if timezone.now() > expires_at:
                new_token = oauth.refresh_token(
                    TEAMS_TOKEN_URL,
                    client_id=settings.TEAMS_CLIENT_ID,
                    client_secret=settings.TEAMS_CLIENT_SECRET
                )
                token_obj.access_token = new_token['access_token']
                token_obj.refresh_token = new_token.get('refresh_token', token_obj.refresh_token)
                token_obj.expires_at = timezone.now() + timezone.timedelta(seconds=new_token['expires_in'])
                token_obj.save()
                oauth = OAuth2Session(settings.TEAMS_CLIENT_ID, token=new_token)

            events = oauth.get(TEAMS_CALENDAR_API).json()
            return Response({'events': events.get('value', [])})
        except TeamsToken.DoesNotExist:
            return Response({'error': 'No token found. Please authenticate.'}, status=400)