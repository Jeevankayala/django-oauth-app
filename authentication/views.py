from django.shortcuts import redirect
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from requests_oauthlib import OAuth2Session
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.models import User
from .models import CustomUser,GoogleToken, ZoomToken, TeamsToken
import logging
from .utils import refresh_oauth_token
from django.core.exceptions import ValidationError
from svix import Webhook, WebhookVerificationError
import json

logger = logging.getLogger(__name__)

# Configuration Constants
GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_SCOPES = ['https://www.googleapis.com/auth/drive.readonly']

ZOOM_AUTH_URL = 'https://zoom.us/oauth/authorize'
ZOOM_TOKEN_URL = 'https://zoom.us/oauth/token'
ZOOM_SCOPES = ['cloud_recording:read:list_user_recordings']

TEAMS_AUTH_URL = f'https://login.microsoftonline.com/{settings.TEAMS_TENANT_ID}/oauth2/v2.0/authorize'
TEAMS_TOKEN_URL = f'https://login.microsoftonline.com/{settings.TEAMS_TENANT_ID}/oauth2/v2.0/token'
TEAMS_SCOPES = [
    'https://graph.microsoft.com/Files.Read.All',
    'https://graph.microsoft.com/OnlineMeetings.Read',
    'https://graph.microsoft.com/OnlineMeetingTranscript.Read.All',
    'https://graph.microsoft.com/Calendars.Read',
    'offline_access'
]



logger = logging.getLogger(__name__)

class ClerkWebhookView(APIView):
    permission_classes = []

    def post(self, request):
        try:
            # Verify Clerk webhook signature
            webhook_secret = settings.CLERK_WEBHOOK_SECRET
            headers = request.META
            svix_id = headers.get('HTTP_SVIX_ID')
            svix_timestamp = headers.get('HTTP_SVIX_TIMESTAMP')
            svix_signature = headers.get('HTTP_SVIX_SIGNATURE')
            raw_body = request.body.decode('utf-8')

            if not all([svix_id, svix_timestamp, svix_signature]):
                logger.error("Missing Svix headers")
                return Response({"error": "Missing webhook headers"}, status=status.HTTP_400_BAD_REQUEST)

            webhook = Webhook(webhook_secret)
            try:
                webhook.verify(raw_body, {
                    "svix-id": svix_id,
                    "svix-timestamp": svix_timestamp,
                    "svix-signature": svix_signature,
                })
            except WebhookVerificationError as e:
                logger.error(f"Webhook verification failed: {str(e)}")
                return Response({"error": "Invalid webhook signature"}, status=status.HTTP_401_UNAUTHORIZED)

            # Process webhook payload
            payload = json.loads(raw_body)
            event_type = payload.get('type')
            data = payload.get('data')

            if event_type == 'user.created' or event_type == 'user.updated':
                user_id = data.get('id')
                email = data.get('email_addresses', [{}])[0].get('email_address', '')
                first_name = data.get('first_name', None)
                last_name = data.get('last_name', None)
                phone_number = data.get('phone_numbers', [{}])[0].get('phone_number', '')
                role = data.get('public_metadata', {}).get('role', '')
                status = data.get('public_metadata', {}).get('status', '')

                if not email or not user_id:
                    logger.warning(f"Missing email or user_id in webhook payload: {data}")
                    return Response({"error": "Invalid user data"}, status=status.HTTP_400_BAD_REQUEST)

                # Update or create CustomUser
                user, created = CustomUser.objects.update_or_create(
                    clerk_id=user_id,
                    defaults={
                        'username': user_id,  # Optional, can be null
                        'email': email,
                        'first_name': first_name,
                        'last_name': last_name,
                        'phone_number': phone_number,
                        'role': role,
                        'status': status,
                    }
                )

                logger.info(f"User {'created' if created else 'updated'}: {user_id}")
                return Response({"message": "User processed successfully"}, status=status.HTTP_200_OK)

            elif event_type == 'user.deleted':
                user_id = data.get('id')
                try:
                    user = CustomUser.objects.get(clerk_id=user_id)
                    user.delete()
                    logger.info(f"User deleted: {user_id}")
                    return Response({"message": "User deleted successfully"}, status=status.HTTP_200_OK)
                except CustomUser.DoesNotExist:
                    logger.warning(f"User not found for deletion: {user_id}")
                    return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

            else:
                logger.info(f"Unhandled webhook event: {event_type}")
                return Response({"message": "Event not handled"}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Webhook processing error: {str(e)}")
            return Response({"error": f"Webhook processing failed: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GoogleAuthView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            try:
                token_obj = GoogleToken.objects.get(user=request.user)
                if token_obj.expires_at > timezone.now():
                    return Response({"message": "Already authenticated with Google"}, status=200)
                if token_obj.refresh_token:
                    try:
                        oauth = refresh_oauth_token(
                            token_obj, 
                            GOOGLE_TOKEN_URL, 
                            settings.GOOGLE_CLIENT_ID, 
                            settings.GOOGLE_CLIENT_SECRET
                        )
                        return Response({"message": "Token refreshed successfully"}, status=200)
                    except ValidationError:
                        pass
            except GoogleToken.DoesNotExist:
                pass
                
            oauth = OAuth2Session(
                settings.GOOGLE_CLIENT_ID,
                redirect_uri=settings.GOOGLE_REDIRECT_URI,
                scope=GOOGLE_SCOPES
            )
            authorization_url, state = oauth.authorization_url(
                GOOGLE_AUTH_URL,
                access_type="offline",
                prompt="consent"
            )
            logger.info(f"Generated auth URL: {authorization_url}")
            request.session['oauth_state'] = state
            request.session['oauth_user_id'] = request.user.clerk_id  # Use Clerk user ID
            return redirect(authorization_url)
        except Exception as e:
            logger.error(f"OAuth initiation failed: {str(e)}")
            return Response({'error': f'OAuth initiation failed: {str(e)}'}, status=500)

class GoogleCallbackView(APIView):
    permission_classes = []
    
    def get(self, request):
        try:
            if 'code' not in request.GET:
                logger.warning("No authorization code provided in callback")
                return Response({'error': 'No authorization code provided'}, status=400)
            
            stored_state = request.session.get('oauth_state')
            user_id = request.session.get('oauth_user_id')
            received_state = request.GET.get('state')
            
            if not stored_state or not user_id:
                logger.warning("Missing state or user_id in session")
                return Response({'error': 'Session expired or invalid. Please try again.'}, status=400)
                
            if stored_state != received_state:
                logger.warning("State mismatch in OAuth callback")
                return Response({'error': 'State mismatch. Possible CSRF attack.'}, status=400)

            try:
                user = CustomUser.objects.get(clerk_id=user_id)  # Use clerk_id
            except CustomUser.DoesNotExist:
                logger.error(f"User with clerk_id {user_id} not found")
                return Response({'error': 'User not found'}, status=404)

            oauth = OAuth2Session(
                settings.GOOGLE_CLIENT_ID,
                redirect_uri=settings.GOOGLE_REDIRECT_URI,
                state=stored_state
            )
            try:
                token = oauth.fetch_token(
                    GOOGLE_TOKEN_URL,
                    code=request.GET.get('code'),
                    client_secret=settings.GOOGLE_CLIENT_SECRET
                )
            except Exception as e:
                logger.error(f"Token exchange failed: {str(e)}")
                return Response({'error': f'Token exchange failed: {str(e)}'}, status=400)

            expires_at = timezone.now() + timezone.timedelta(seconds=token['expires_in'])
            google_token, created = GoogleToken.objects.update_or_create(
                user=user,
                defaults={
                    'access_token': token['access_token'],
                    'refresh_token': token.get('refresh_token', ''),
                    'expires_at': expires_at
                }
            )
            
            if 'oauth_state' in request.session:
                del request.session['oauth_state']
            if 'oauth_user_id' in request.session:
                del request.session['oauth_user_id']
                
            logger.info("Google integration successful")
            return Response({"message": "Google integration successful"}, status=200)

        except Exception as e:
            logger.error(f"OAuth callback error: {str(e)}")
            return Response({'error': f'OAuth callback error: {str(e)}'}, status=500)

class ZoomAuthView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            try:
                token_obj = ZoomToken.objects.get(user=request.user)
                if token_obj.expires_at > timezone.now():
                    return Response({"message": "Already authenticated with Zoom"}, status=200)
                if token_obj.refresh_token:
                    try:
                        oauth = refresh_oauth_token(
                            token_obj, 
                            ZOOM_TOKEN_URL, 
                            settings.ZOOM_CLIENT_ID, 
                            settings.ZOOM_CLIENT_SECRET
                        )
                        return Response({"message": "Token refreshed successfully"}, status=200)
                    except ValidationError:
                        pass
            except ZoomToken.DoesNotExist:
                pass
                
            oauth = OAuth2Session(
                settings.ZOOM_CLIENT_ID,
                redirect_uri=settings.ZOOM_REDIRECT_URI,
                scope=ZOOM_SCOPES
            )
            authorization_url, state = oauth.authorization_url(
                ZOOM_AUTH_URL,
                access_type="offline",
                prompt="consent"
            )
            logger.info(f"Generated Zoom auth URL: {authorization_url}")
            request.session['oauth_state'] = state
            request.session['oauth_user_id'] = request.user.clerk_id  # Use Clerk user ID
            return redirect(authorization_url)
        except Exception as e:
            logger.error(f"Zoom OAuth initiation failed: {str(e)}")
            return Response({'error': f'OAuth initiation failed: {str(e)}'}, status=500)

class ZoomCallbackView(APIView):
    permission_classes = []
    
    def get(self, request):
        try:
            if 'code' not in request.GET:
                logger.warning("No authorization code provided in callback")
                return Response({'error': 'No authorization code provided'}, status=400)
            
            stored_state = request.session.get('oauth_state')
            user_id = request.session.get('oauth_user_id')
            received_state = request.GET.get('state')
            
            if not stored_state or not user_id:
                logger.warning("Missing state or user_id in session")
                return Response({'error': 'Session expired or invalid. Please try again.'}, status=400)
                
            if stored_state != received_state:
                logger.warning("State mismatch in OAuth callback")
                return Response({'error': 'State mismatch. Possible CSRF attack.'}, status=400)

            try:
                user = CustomUser.objects.get(clerk_id=user_id)  # Use clerk_id
            except CustomUser.DoesNotExist:
                logger.error(f"User with clerk_id {user_id} not found")
                return Response({'error': 'User not found'}, status=404)

            oauth = OAuth2Session(
                settings.ZOOM_CLIENT_ID,
                redirect_uri=settings.ZOOM_REDIRECT_URI,
                state=stored_state
            )
            try:
                token = oauth.fetch_token(
                    ZOOM_TOKEN_URL,
                    code=request.GET.get('code'),
                    client_secret=settings.ZOOM_CLIENT_SECRET,
                    include_client_id=True
                )
            except Exception as e:
                logger.error(f"Token exchange failed: {str(e)}")
                return Response({'error': f'Token exchange failed: {str(e)}'}, status=400)

            expires_at = timezone.now() + timezone.timedelta(seconds=token['expires_in'])
            zoom_token, created = ZoomToken.objects.update_or_create(
                user=user,
                defaults={
                    'access_token': token['access_token'],
                    'refresh_token': token.get('refresh_token', ''),
                    'expires_at': expires_at
                }
            )
            
            if 'oauth_state' in request.session:
                del request.session['oauth_state']
            if 'oauth_user_id' in request.session:
                del request.session['oauth_user_id']
                
            logger.info("Zoom integration successful")
            return Response({"message": "Zoom integration successful"}, status=200)

        except Exception as e:
            logger.error(f"OAuth callback error: {str(e)}")
            return Response({'error': f'OAuth callback error: {str(e)}'}, status=500)

class TeamsAuthView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        try:
            try:
                token_obj = TeamsToken.objects.get(user=request.user)
                if token_obj.expires_at > timezone.now():
                    return Response({"message": "Already authenticated with Microsoft Teams"}, status=200)
                if token_obj.refresh_token:
                    try:
                        oauth = refresh_oauth_token(
                            token_obj, 
                            TEAMS_TOKEN_URL, 
                            settings.TEAMS_CLIENT_ID, 
                            settings.TEAMS_CLIENT_SECRET
                        )
                        return Response({"message": "Token refreshed successfully"}, status=200)
                    except ValidationError:
                        pass
            except TeamsToken.DoesNotExist:
                pass
                
            oauth = OAuth2Session(
                settings.TEAMS_CLIENT_ID,
                redirect_uri=settings.TEAMS_REDIRECT_URI,
                scope=TEAMS_SCOPES
            )
            authorization_url, state = oauth.authorization_url(TEAMS_AUTH_URL)

            logger.info(f"Generated Microsoft Teams auth URL: {authorization_url}")
            request.session['oauth_state'] = state
            request.session['oauth_user_id'] = request.user.clerk_id  # Use Clerk user ID
            return redirect(authorization_url)
        except Exception as e:
            logger.error(f"Microsoft Teams OAuth initiation failed: {str(e)}")
            return Response({'error': f'OAuth initiation failed: {str(e)}'}, status=500)

class TeamsCallbackView(APIView):
    permission_classes = []
    
    def get(self, request):
        try:
            if 'code' not in request.GET:
                logger.warning("No authorization code provided in callback")
                return Response({'error': 'No authorization code provided'}, status=400)
            
            stored_state = request.session.get('oauth_state')
            user_id = request.session.get('oauth_user_id')
            received_state = request.GET.get('state')
            
            if not stored_state or not user_id:
                logger.warning("Missing state or user_id in session")
                return Response({'error': 'Session expired or invalid. Please try again.'}, status=400)
                
            if stored_state != received_state:
                logger.warning("State mismatch in OAuth callback")
                return Response({'error': 'State mismatch. Possible CSRF attack.'}, status=400)

            try:
                user = CustomUser.objects.get(clerk_id=user_id)  # Use clerk_id
            except CustomUser.DoesNotExist:
                logger.error(f"User with clerk_id {user_id} not found")
                return Response({'error': 'User not found'}, status=404)

            oauth = OAuth2Session(
                settings.TEAMS_CLIENT_ID,
                redirect_uri=settings.TEAMS_REDIRECT_URI,
                state=stored_state
            )
            try:
                token = oauth.fetch_token(
                    TEAMS_TOKEN_URL,
                    code=request.GET.get('code'),
                    client_secret=settings.TEAMS_CLIENT_SECRET
                )
            except Exception as e:
                logger.error(f"Token exchange failed: {str(e)}")
                return Response({'error': f'Token exchange failed: {str(e)}'}, status=400)

            expires_at = timezone.now() + timezone.timedelta(seconds=token['expires_in'])
            teams_token, created = TeamsToken.objects.update_or_create(
                user=user,
                defaults={
                    'access_token': token['access_token'],
                    'refresh_token': token.get('refresh_token', ''),
                    'expires_at': expires_at
                }
            )
            
            if 'oauth_state' in request.session:
                del request.session['oauth_state']
            if 'oauth_user_id' in request.session:
                del request.session['oauth_user_id']
            
            logger.info("Microsoft Teams integration successful")
            return Response({"message": "Microsoft Teams integration successful"}, status=200)

        except Exception as e:
            logger.error(f"OAuth callback error: {str(e)}")
            return Response({'error': f'OAuth callback error: {str(e)}'}, status=500)

class GoogleDeleteView(APIView):
    permission_classes = [IsAuthenticated]
    
    def delete(self, request):
        try:
            token_obj = GoogleToken.objects.get(user=request.user)
            token_obj.delete()
            logger.info(f"Google token deleted for user {request.user.clerk_id}")
            return Response({"message": "Google integration removed successfully"}, status=200)
        except GoogleToken.DoesNotExist:
            logger.warning(f"No Google token found for user {request.user.clerk_id}")
            return Response({"message": "No Google integration found"}, status=404)
        except Exception as e:
            logger.error(f"Google token deletion failed: {str(e)}")
            return Response({'error': f'Deletion failed: {str(e)}'}, status=500)

class ZoomDeleteView(APIView):
    permission_classes = [IsAuthenticated]
    
    def delete(self, request):
        try:
            token_obj = ZoomToken.objects.get(user=request.user)
            token_obj.delete()
            logger.info(f"Zoom token deleted for user {request.user.clerk_id}")
            return Response({"message": "Zoom integration removed successfully"}, status=200)
        except ZoomToken.DoesNotExist:
            logger.warning(f"No Zoom token found for user {request.user.clerk_id}")
            return Response({"message": "No Zoom integration found"}, status=404)
        except Exception as e:
            logger.error(f"Zoom token deletion failed: {str(e)}")
            return Response({'error': f'Deletion failed: {str(e)}'}, status=500)

class TeamsDeleteView(APIView):
    permission_classes = [IsAuthenticated]
    
    def delete(self, request):
        try:
            token_obj = TeamsToken.objects.get(user=request.user)
            token_obj.delete()
            logger.info(f"Teams token deleted for user {request.user.clerk_id}")
            return Response({"message": "Microsoft Teams integration removed successfully"}, status=200)
        except TeamsToken.DoesNotExist:
            logger.warning(f"No Teams token found for user {request.user.clerk_id}")
            return Response({"message": "No Microsoft Teams integration found"}, status=404)
        except Exception as e:
            logger.error(f"Teams token deletion failed: {str(e)}")
            return Response({'error': f'Deletion failed: {str(e)}'}, status=500)