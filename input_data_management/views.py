import uuid
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from requests_oauthlib import OAuth2Session
from django.conf import settings
from django.utils import timezone
from .models import GoogleMeetTranscript, ZoomTranscript, YouTubeTranscript, GoogleDriveWebhook
import urllib
import pendulum
from dateutil.parser import isoparse
import logging
from authentication.utils import refresh_oauth_token
from .utils import clean_google_transcript, clean_zoom_transcript, clean_teams_transcript
from authentication.models import GoogleToken, ZoomToken, TeamsToken
import yt_dlp
from faster_whisper import WhisperModel
from urllib.parse import urlparse, parse_qs
import os
from googleapiclient.discovery import build
from rest_framework.decorators import api_view
import re
from datetime import datetime
from django.db import transaction
from .utils import get_meet_folder_id
from .tasks import scrape_with_exclude
from .initializers import pinecone_index, embeddings, text_splitter
from celery.result import AsyncResult
from django.core.exceptions import ValidationError


logger = logging.getLogger(__name__)

GOOGLE_DRIVE_API = 'https://www.googleapis.com/drive/v3/files'
GOOGLE_DRIVE_CONTENT_API = 'https://www.googleapis.com/drive/v3/files/{file_id}/export'
ZOOM_RECORDINGS_API = 'https://api.zoom.us/v2/users/me/recordings'
ZOOM_TOKEN_URL = 'https://zoom.us/oauth/token'
TEAMS_ONEDRIVE_RECORDINGS_API = 'https://graph.microsoft.com/v1.0/me/drive/root:/Recordings:/children'
TEAMS_MEETINGS_API = 'https://graph.microsoft.com/v1.0/me/onlineMeetings'
TEAMS_CALENDAR_API = 'https://graph.microsoft.com/v1.0/me/events'
TEAMS_TOKEN_URL = f'https://login.microsoftonline.com/{settings.TEAMS_TENANT_ID}/oauth2/v2.0/token'


@api_view(['POST'])
def google_drive_webhook(request):
    """Handle Google Drive webhook notifications for new recordings."""
    try:
        channel_id = request.headers.get('X-Goog-Channel-ID')
        channel_token = request.headers.get('X-Goog-Channel-Token')
        resource_state = request.headers.get('X-Goog-Resource-State')
        expiry = request.headers.get('X-Goog-Channel-Expiry')

        logger.info(f"Received Google Drive webhook: channel_id={channel_id}, resource_state={resource_state}")

        # Ignore non-relevant resource states
        if resource_state not in ['update', 'add', 'sync']:
            logger.debug(f"Ignoring webhook with resource_state {resource_state}")
            return Response({'status': 'ignored'})

        # Check webhook expiry
        if expiry:
            expiry_date = datetime.fromisoformat(expiry.replace('Z', '+00:00'))
            if expiry_date < timezone.now() + timezone.timedelta(days=1):
                logger.warning(f"Webhook {channel_id} expiring soon: {expiry}")
                from .tasks import renew_webhook
                renew_webhook.delay(channel_id)

        # Validate webhook
        try:
            webhook = GoogleDriveWebhook.objects.get(channel_id=channel_id)
        except GoogleDriveWebhook.DoesNotExist:
            logger.error(f"Webhook with channel_id {channel_id} not found")
            return Response({'error': 'Invalid webhook'}, status=400)

        if webhook.channel_token != channel_token:
            logger.error(f"Invalid channel token for webhook {channel_id}")
            return Response({'error': 'Invalid webhook token'}, status=403)

        # Get user and OAuth token
        user = webhook.user
        token_obj = GoogleToken.objects.get(user=user)
        oauth = refresh_oauth_token(
            token_obj, 'https://oauth2.googleapis.com/token',
            settings.GOOGLE_CLIENT_ID, settings.GOOGLE_CLIENT_SECRET
        )

        # Find Meet Recordings folder
        folder_id = get_meet_folder_id(oauth, user.id)
        if not folder_id:
            logger.error(f"Meet Recordings folder not found for user {user.id}")
            return Response({'error': 'Meet Recordings folder not found'}, status=404)

        # Fetch recent changes
        changes_response = oauth.get(
            f"{GOOGLE_DRIVE_API}/changes",
            params={
                'pageToken': webhook.last_page_token,
                'spaces': 'drive',
                'includeItemsFromAllDrives': True
            }
        ).json()
        changes = changes_response.get('changes', [])
        new_page_token = changes_response.get('nextPageToken') or changes_response.get('newStartPageToken') or webhook.last_page_token

        # Update page token
        webhook.last_page_token = new_page_token
        webhook.save()

        # Process new video files
        for change in changes:
            file = change.get('file', {})
            if (
                file.get('mimeType', '').startswith('video/') and
                folder_id in file.get('parents', []) and
                not change.get('removed', False)
            ):
                file_id = file['id']
                logger.info(f"Detected new video file {file_id} for user {user.id}")
                from .tasks import process_new_recording
                process_new_recording.delay(user.id, file_id)

        return Response({'status': 'ok'})
    except GoogleToken.DoesNotExist:
        logger.error(f"No Google token found for user {user.id}")
        return Response({'error': 'No token found. Please authenticate with Google.'}, status=400)
    except Exception as e:
        logger.error(f"Error handling Google Drive webhook: {str(e)}", exc_info=True)
        return Response({'error': 'Internal error'}, status=500)


class GoogleRecordingsView(APIView):
    """Fetch Google Meet recordings for a user."""
    permission_classes = [IsAuthenticated]

    def validate_date(self, date_str, param_name):
        """Validate date string in YYYY-MM-DD format."""
        try:
            datetime.strptime(date_str, '%Y-%m-%d')
            return date_str
        except ValueError:
            logger.error(f"Invalid date format for {param_name}: {date_str}")
            raise ValidationError(f"Invalid date format for {param_name}. Use YYYY-MM-DD.")

    def get(self, request):
        try:
            user = request.user
            logger.info(f"Fetching Google Meet recordings for user {user.id}")

            # Get OAuth token
            try:
                token_obj = GoogleToken.objects.get(user=user)
            except GoogleToken.DoesNotExist:
                logger.error(f"No Google token found for user {user.id}")
                return Response({'error': 'No token found. Please authenticate with Google.'}, status=400)

            oauth = refresh_oauth_token(
                token_obj, 'https://oauth2.googleapis.com/token', settings.GOOGLE_CLIENT_ID, settings.GOOGLE_CLIENT_SECRET
            )

            # Set and validate date range
            from_date = request.GET.get('from', (timezone.now() - timezone.timedelta(days=30)).strftime('%Y-%m-%d'))
            to_date = request.GET.get('to', timezone.now().strftime('%Y-%m-%d'))
            from_date = self.validate_date(from_date, 'from')
            to_date = self.validate_date(to_date, 'to')
            logger.info(f"Querying recordings from {from_date} to {to_date}")

            # Find Meet Recordings folder
            folder_query = "name='Meet Recordings' and mimeType='application/vnd.google-apps.folder'"
            folder_response = oauth.get(GOOGLE_DRIVE_API, params={'q': folder_query, 'fields': 'files(id)'}).json()
            folder_id = folder_response.get('files', [{}])[0].get('id', None)
            if not folder_id:
                logger.error(f"Meet Recordings folder not found for user {user.id}")
                return Response({'error': 'Meet Recordings folder not found'}, status=404)

            # Fetch video recordings
            video_query = f"'{folder_id}' in parents and mimeType contains 'video/' and createdTime >= '{from_date}T00:00:00Z' and createdTime <= '{to_date}T23:59:59Z'"
            logger.debug(f"Video query: {video_query}")
            video_response = oauth.get(
                GOOGLE_DRIVE_API,
                params={
                    'q': video_query,
                    'fields': 'files(id,name,createdTime,webViewLink,size,webContentLink)',
                    'orderBy': 'createdTime desc',
                    'pageSize': 30
                }
            )

            if video_response.status_code != 200:
                logger.error(f"Failed to fetch Google recordings: {video_response.text}")
                return Response({'error': 'Failed to fetch recordings'}, status=video_response.status_code)

            recordings = video_response.json().get('files', [])
            logger.info(f"Retrieved {len(recordings)} video recordings for user {user.id}")

            # Check existing transcripts
            existing_transcripts = {
                transcript.file_id: transcript
                for transcript in GoogleMeetTranscript.objects.filter(user=user)
            }

            new_recording_ids = [rec['id'] for rec in recordings if rec['id'] not in existing_transcripts]
            transcript_mime_types = [
                "text/plain", "application/vnd.google-apps.document", "text/vtt",
                "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "text/srt"
            ]

            transcripts = {}
            if new_recording_ids:
                mime_type_query = " or ".join([f"mimeType='{mime}'" for mime in transcript_mime_types])
                transcript_query = f"'{folder_id}' in parents and ({mime_type_query})"
                logger.debug(f"Transcript query: {transcript_query}")
                transcript_response = oauth.get(
                    GOOGLE_DRIVE_API,
                    params={'q': transcript_query, 'fields': 'files(id,name,createdTime,webViewLink,size,mimeType,webContentLink)'}
                )
                if transcript_response.status_code == 200:
                    transcripts = {rec['name']: rec for rec in transcript_response.json().get('files', [])}
                else:
                    logger.error(f"Failed to fetch transcripts: {transcript_response.text}")

            processed_recordings = []
            for rec in recordings:
                file_id = rec['id']
                video_name = rec['name']
                created_time = isoparse(rec['createdTime'])

                if file_id in existing_transcripts:
                    transcript = existing_transcripts[file_id]
                    processed_recordings.append({
                        'file_id': file_id,
                        'name': video_name,
                        'created_date': rec['createdTime'],
                        'view_link': rec['webViewLink'],
                        'size': rec.get('size', 'Unknown'),
                        'status': transcript.status,
                        'is_vector_stored': transcript.is_vector_stored,
                        'source': 'database',
                        'error': 'Recording already processed'
                    })
                    continue

                transcript_name = f"{video_name} - Transcript" if " - Recording" not in video_name else video_name.replace(" - Recording", " - Transcript")
                transcript_content = ""
                transcript_status = "missing"
                is_vector_stored = False

                if transcript_name in transcripts:
                    transcript_rec = transcripts[transcript_name]
                    transcript_file_id = transcript_rec['id']
                    mime_type = transcript_rec['mimeType']

                    if mime_type == "application/vnd.google-apps.document":
                        export_url = f"https://www.googleapis.com/drive/v3/files/{transcript_file_id}/export"
                        content_response = oauth.get(export_url, params={'mimeType': 'text/plain'})
                        if content_response.status_code == 200:
                            transcript_content = clean_google_transcript(content_response.text)
                            transcript_status = "available"
                        else:
                            logger.error(f"Failed to export Google Doc transcript {transcript_file_id}: {content_response.text}")

                    elif mime_type in ["text/plain", "text/vtt", "text/srt"]:
                        file_url = f"https://www.googleapis.com/drive/v3/files/{transcript_file_id}?alt=media"
                        content_response = oauth.get(file_url)
                        if content_response.status_code == 200:
                            transcript_content = clean_google_transcript(content_response.text)
                            transcript_status = "available"
                        else:
                            logger.error(f"Failed to download transcript {transcript_file_id}: {content_response.text}")

                # Store metadata in PostgreSQL
                with transaction.atomic():
                    transcript_obj = GoogleMeetTranscript.objects.create(
                        user=user,
                        file_id=file_id,
                        video_url=rec['webViewLink'],
                        status=transcript_status,
                        source_name=video_name,
                        created_time=created_time,
                        file_size=rec.get('size', 'Unknown'),
                        is_vector_stored=False,
                        processed_at=timezone.now()
                    )

                # Store transcript in Pinecone if available
                if transcript_content:
                    try:
                        chunks = text_splitter.split_text(transcript_content)
                        chunk_embeddings = embeddings.encode(chunks, convert_to_numpy=True)
                        vectors = [
                            {
                                'id': f"google_{file_id}_{i}",
                                'values': embedding.tolist(),
                                'metadata': {
                                    'user_id': user.id,
                                    'file_id': file_id,
                                    'chunk_text': chunk,
                                    'meeting_name': video_name,
                                    'video_url': rec['webViewLink'],
                                    'created_time': rec['createdTime'],
                                    'source': 'google'
                                }
                            }
                            for i, (chunk, embedding) in enumerate(zip(chunks, chunk_embeddings))
                        ]
                        upsert_response = pinecone_index.upsert(vectors=vectors, async_req=True)
                        upsert_response.get()
                        logger.info(f"Stored {len(vectors)} transcript chunks in Pinecone for Google recording {file_id}")
                        transcript_obj.is_vector_stored = True
                        transcript_obj.save()
                        is_vector_stored = True
                    except Exception as e:
                        logger.error(f"Failed to upsert to Pinecone for Google recording {file_id}: {str(e)}")
                        transcript_obj.status = 'failed'
                        transcript_obj.save()

                processed_recordings.append({
                    'file_id': file_id,
                    'name': video_name,
                    'created_date': rec['createdTime'],
                    'view_link': rec['webViewLink'],
                    'size': rec.get('size', 'Unknown'),
                    'status': transcript_status,
                    'is_vector_stored': is_vector_stored,
                    'source': 'api'
                })

            return Response({'recordings': processed_recordings})

        except ValidationError as e:
            return Response({'error': str(e)}, status=400)
        except Exception as e:
            logger.error(f"Error fetching Google recordings for user {user.id}: {str(e)}")
            return Response({'error': f'An error occurred: {str(e)}'}, status=500)        


class ZoomRecordingsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user = request.user
            token_obj = ZoomToken.objects.get(user=user)
            oauth = refresh_oauth_token(
                token_obj, ZOOM_TOKEN_URL, settings.ZOOM_CLIENT_ID, settings.ZOOM_CLIENT_SECRET
            )

            existing_transcripts = {
                transcript.file_id: transcript
                for transcript in ZoomTranscript.objects.filter(user=user)
            }

            from_date = request.GET.get('from', (timezone.now() - timezone.timedelta(days=30)).strftime('%Y-%m-%d'))
            to_date = request.GET.get('to', timezone.now().strftime('%Y-%m-%d'))

            response = oauth.get(
                ZOOM_RECORDINGS_API,
                params={'from': from_date, 'to': to_date, 'page_size': 30}
            )

            if response.status_code != 200:
                logger.error(f"Failed to fetch Zoom recordings: {response.text}")
                return Response({'error': 'Failed to fetch recordings'}, status=response.status_code)

            recordings_data = response.json()
            meetings = recordings_data.get('meetings', [])
            processed_recordings = []

            for meeting in meetings:
                recording_files = meeting.get('recording_files', [])
                video_file = next((f for f in recording_files if f['file_type'] == 'MP4'), None)
                transcript_file = next((f for f in recording_files if f['file_type'] == 'TRANSCRIPT'), None)

                if not video_file:
                    continue

                file_id = video_file['id']
                meeting_id = str(meeting['id'])
                start_time = isoparse(meeting['start_time'])

                if file_id in existing_transcripts:
                    transcript = existing_transcripts[file_id]
                    processed_recordings.append({
                        'meeting_id': meeting_id,
                        'topic': meeting['topic'],
                        'start_time': meeting['start_time'],
                        'file_id': file_id,
                        'download_url': video_file['download_url'],
                        'file_size': video_file.get('file_size'),
                        'status': transcript.status,
                        'is_vector_stored': transcript.is_vector_stored,
                        'source': 'database',
                        'error': 'Recording already processed'
                    })
                    continue

                transcript_content = ""
                transcript_status = "missing"
                is_vector_stored = False

                if transcript_file:
                    transcript_response = oauth.get(transcript_file['download_url'])
                    if transcript_response.status_code == 200:
                        transcript_content = clean_zoom_transcript(transcript_response.text)
                        transcript_status = "available"
                    else:
                        logger.error(f"Failed to fetch Zoom transcript for file {file_id}: {transcript_response.text}")

                # Store metadata in PostgreSQL
                with transaction.atomic():
                    transcript_obj = ZoomTranscript.objects.create(
                        user=user,
                        file_id=file_id,
                        meeting_id=meeting_id,
                        video_url=video_file['download_url'],
                        status=transcript_status,
                        source_name=meeting['topic'],
                        start_time=start_time,
                        file_size=video_file.get('file_size'),
                        is_vector_stored=False,
                        processed_at=timezone.now()
                    )

                # Store transcript in Pinecone if available
                if transcript_content:
                    try:
                        chunks = text_splitter.split_text(transcript_content)
                        chunk_embeddings = embeddings.encode(chunks, convert_to_numpy=True)
                        vectors = [
                            {
                                'id': f"zoom_{file_id}_{i}",
                                'values': embedding.tolist(),
                                'metadata': {
                                    'user_id': user.id,
                                    'file_id': file_id,
                                    'chunk_text': chunk,
                                    'meeting_name': meeting['topic'],
                                    'video_url': video_file['download_url'],
                                    'start_time': meeting['start_time'],
                                    'source': 'zoom'
                                }
                            }
                            for i, (chunk, embedding) in enumerate(zip(chunks, chunk_embeddings))
                        ]
                        upsert_response = pinecone_index.upsert(vectors=vectors, async_req=True)
                        upsert_response.get()
                        logger.info(f"Stored {len(vectors)} transcript chunks in Pinecone for Zoom recording {file_id}")
                        transcript_obj.is_vector_stored = True
                        transcript_obj.save()
                        is_vector_stored = True
                    except Exception as e:
                        logger.error(f"Failed to upsert to Pinecone for Zoom recording {file_id}: {str(e)}")
                        transcript_obj.status = 'failed'
                        transcript_obj.save()

                processed_recordings.append({
                    'meeting_id': meeting_id,
                    'topic': meeting['topic'],
                    'start_time': meeting['start_time'],
                    'file_id': file_id,
                    'download_url': video_file['download_url'],
                    'file_size': video_file.get('file_size'),
                    'status': transcript_status,
                    'is_vector_stored': is_vector_stored,
                    'source': 'api'
                })

            return Response({'recordings': processed_recordings})

        except ZoomToken.DoesNotExist:
            return Response({'error': 'No token found. Please authenticate with Zoom.'}, status=400)
        except Exception as e:
            logger.error(f"Error fetching Zoom recordings: {str(e)}")
            return Response({'error': f'An error occurred: {str(e)}'}, status=500)


# View to fetch Microsoft Teams recordings and transcripts
class TeamsRecordingsView(APIView):
    """
    Fetches Teams meeting recordings with their meeting IDs and transcripts.
    Returns a flat list with proper correlation between recordings and transcripts.
    """
    def get(self, request):
        try:
            # Get and refresh the OAuth token
            token_obj = TeamsToken.objects.get(user=request.user)
            oauth = refresh_oauth_token(token_obj, TEAMS_TOKEN_URL, settings.TEAMS_CLIENT_ID, settings.TEAMS_CLIENT_SECRET)
            if oauth is None:
                return Response({'error': 'Token refresh failed. Please re-authenticate.'}, status=401)

            # Step 1: Fetch Calendar Events with Online Meeting info
            seven_days_ago = (pendulum.now('UTC') - pendulum.duration(days=7)).to_iso8601_string()
            events_url = f"{TEAMS_CALENDAR_API}?$filter=start/dateTime ge '{seven_days_ago}'&$select=id,subject,start,end,onlineMeeting"
            events_response = oauth.get(events_url)
            
            if events_response.status_code != 200:
                logger.error(f"Failed to fetch events: {events_response.text}")
                return Response({'error': 'Failed to fetch calendar events'}, status=events_response.status_code)

            events = events_response.json().get('value', [])
            logger.info(f"Found {len(events)} calendar events in the last 7 days")
            
            # Dictionary to store meeting data
            meeting_data = {}  # Key: meeting_id, Value: meeting details
            
            # Step 2: Process events with online meetings
            for event in events:
                if 'onlineMeeting' in event and 'joinUrl' in event['onlineMeeting']:
                    join_url = event['onlineMeeting']['joinUrl']
                    
                    # Use a properly encoded filter for the join URL
                    encoded_url = urllib.parse.quote(join_url)
                    meeting_url = f"{TEAMS_MEETINGS_API}?$filter=JoinWebUrl eq '{encoded_url}'"
                    
                    meeting_response = oauth.get(meeting_url)
                    if meeting_response.status_code == 200:
                        meetings = meeting_response.json().get('value', [])
                        if meetings:
                            meeting_id = meetings[0]['id']
                            # Store meeting details with event info for better matching
                            meeting_data[meeting_id] = {
                                'meeting_id': meeting_id,
                                'subject': event.get('subject', 'Unknown Meeting'),
                                'start_time': event['start']['dateTime'],
                                'end_time': event['end']['dateTime'],
                                'join_url': join_url,
                                'event_id': event.get('id'),
                                'recordings': [],
                                'transcripts': []
                            }
            
            logger.info(f"Found {len(meeting_data)} online meetings from calendar events")
            
            # Step 3: Fetch recordings and transcripts for each meeting
            for meeting_id, data in meeting_data.items():
                # Fetch recordings for the meeting
                recordings_url = f"{TEAMS_MEETINGS_API}/{meeting_id}/recordings"
                recordings_response = oauth.get(recordings_url)
                
                if recordings_response.status_code == 200:
                    recordings = recordings_response.json().get('value', [])
                    for recording in recordings:
                        meeting_data[meeting_id]['recordings'].append({
                            'file_id': recording.get('id'),
                            'name': f"{data['subject']} - {pendulum.parse(recording.get('createdDateTime')).format('YYYY-MM-DD HH:mm')}.mp4",
                            'created_date': recording.get('createdDateTime'),
                            'download_url': recording.get('contentUrl'),
                            'size': recording.get('fileSize', 0)
                        })
                
                # Fetch transcripts for the meeting
                transcripts = self.fetch_transcripts(meeting_id, oauth)
                meeting_data[meeting_id]['transcripts'] = transcripts
            
            # Step 4: Fetch OneDrive Recordings as fallback
            recordings_response = oauth.get(TEAMS_ONEDRIVE_RECORDINGS_API)
            if recordings_response.status_code != 200:
                logger.error(f"Failed to fetch OneDrive recordings: {recordings_response.text}")
                # Continue with what we have rather than failing completely
            else:
                all_recordings = recordings_response.json().get('value', [])
                logger.info(f"Found {len(all_recordings)} total recordings in OneDrive")
                
                # Filter recordings by date in Python code
                seven_days_ago = pendulum.now('UTC') - pendulum.duration(days=7)
                filtered_recordings = []
                
                for file in all_recordings:
                    if file['name'].endswith('.mp4'):
                        try:
                            file_time = pendulum.parse(file['createdDateTime'])
                            if file_time >= seven_days_ago:
                                filtered_recordings.append(file)
                        except Exception as e:
                            logger.warning(f"Could not parse date for file {file['name']}: {str(e)}")
                
                logger.info(f"Found {len(filtered_recordings)} recordings in OneDrive from the last 7 days")
                
                # Process filtered OneDrive recordings
                for file in filtered_recordings:
                    file_time = pendulum.parse(file['createdDateTime'])
                    matched = False
                    
                    # Try to match with meeting data based on time proximity
                    for meeting_id, data in meeting_data.items():
                        meeting_start = pendulum.parse(data['start_time'])
                        meeting_end = pendulum.parse(data['end_time'])
                        
                        # Check if file creation time is within meeting time or up to 15 minutes after
                        if (meeting_start <= file_time <= meeting_end.add(minutes=15)):
                            # Add to existing meeting if not already added
                            if not any(r.get('file_id') == file['id'] for r in data['recordings']):
                                meeting_data[meeting_id]['recordings'].append({
                                    'file_id': file['id'],
                                    'name': file['name'],
                                    'created_date': file['createdDateTime'],
                                    'download_url': file.get('@microsoft.graph.downloadUrl'),
                                    'size': file['size']
                                })
                            matched = True
                            break
                    
                    # Add unmatched recordings
                    if not matched:
                        # Create a "standalone" recording entry
                        new_id = f"standalone-{uuid.uuid4()}"
                        meeting_data[new_id] = {
                            'meeting_id': None,
                            'subject': file['name'].replace('.mp4', ''),
                            'start_time': file['createdDateTime'],
                            'end_time': file['createdDateTime'],
                            'recordings': [{
                                'file_id': file['id'],
                                'name': file['name'],
                                'created_date': file['createdDateTime'],
                                'download_url': file.get('@microsoft.graph.downloadUrl'),
                                'size': file['size']
                            }],
                            'transcripts': []  # No transcripts for standalone recordings
                        }
            
            # Step 5: Build the final response structure
            processed_recordings = []
            
            for meeting_id, data in meeting_data.items():
                # Include recordings with their associated transcripts
                for recording in data['recordings']:
                    processed_recordings.append({
                        'file_id': recording['file_id'],
                        'name': recording['name'],
                        'created_date': recording['created_date'],
                        'download_url': recording['download_url'],
                        'size': recording['size'],
                        'meeting_id': data['meeting_id'],
                        'subject': data['subject'],
                        'start_time': data['start_time'],
                        'transcripts': data['transcripts']
                    })
            
            # Sort recordings by creation date (newest first)
            processed_recordings.sort(key=lambda x: x['created_date'], reverse=True)
            
            return Response({'recordings': processed_recordings})

        except TeamsToken.DoesNotExist:
            return Response({'error': 'Please authenticate with Microsoft Teams.'}, status=400)
        except Exception as e:
            logger.error(f"Error fetching Teams data: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            return Response({'error': 'An error occurred while fetching recordings.'}, status=500)
        
    def fetch_transcripts(self, meeting_id: str, oauth: OAuth2Session) -> list:
        """Fetches transcripts for a given meeting ID."""
        try:
            transcripts_url = f"{TEAMS_MEETINGS_API}/{meeting_id}/transcripts"
            transcripts_response = oauth.get(transcripts_url)
            if transcripts_response.status_code != 200:
                logger.error(f"Failed to fetch transcripts for {meeting_id}: {transcripts_response.text}")
                return []

            transcripts = transcripts_response.json().get('value', [])
            if not transcripts:
                logger.info(f"No transcripts for {meeting_id}")
                return []

            processed_transcripts = []
            for transcript in transcripts:
                content_url = transcript.get('transcriptContentUrl')
                if content_url:
                    headers = {'Accept': 'text/vtt'}
                    content_response = oauth.get(content_url, headers=headers)
                    if content_response.status_code == 200:
                        processed_transcripts.append({
                            'id': transcript['id'],
                            'created_date_time': transcript['createdDateTime'],
                            'transcript': clean_teams_transcript(content_response.text)
                        })
                    else:
                        logger.warning(f"Failed to fetch transcript {transcript['id']}: {content_response.text}")
            return processed_transcripts
        except Exception as e:
            logger.error(f"Error fetching transcripts for {meeting_id}: {e}")
            return []
        

os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"


class YouTubeTranscriptsView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Process a YouTube video or channel URL to generate and store transcripts."""
        try:
            youtube_url = request.data.get('youtube_url')
            video_count = request.data.get('video_count', 5)  # Default to 5 for channel URLs
            if not youtube_url:
                return Response({'error': 'YouTube URL is required'}, status=400)

            # Validate video_count for channel URLs
            if not self.is_video_url(youtube_url):
                video_count = max(5, min(int(video_count), 20))  # Enforce 5-20 range
            else:
                video_count = 1  # Single video

            user = request.user
            processed_transcripts = []
            processed_video_ids = set()

            # Check existing transcripts in PostgreSQL
            existing_transcripts = {
                transcript.video_id: transcript
                for transcript in YouTubeTranscript.objects.filter(user=user)
            }

            if self.is_video_url(youtube_url):
                # Process single video
                transcript_data = self.process_single_video(
                    youtube_url, processed_video_ids, user, existing_transcripts, None
                )
                if transcript_data:
                    processed_transcripts.append(transcript_data)
            else:
                # Process channel (latest N videos)
                video_urls = self.get_latest_channel_videos(youtube_url, video_count)
                if not video_urls:
                    return Response({'error': 'No videos found for the channel'}, status=404)

                for idx, url in enumerate(video_urls, 1):
                    transcript_data = self.process_single_video(
                        url, processed_video_ids, user, existing_transcripts, youtube_url
                    )
                    if transcript_data:
                        transcript_data['video_number'] = idx
                        processed_transcripts.append(transcript_data)

            return Response({'transcripts': processed_transcripts})

        except Exception as e:
            logger.error(f"Error processing YouTube URL: {str(e)}", exc_info=True)
            return Response({'error': f'Internal error: {str(e)}'}, status=500)

    def is_video_url(self, url):
        """Check if the URL is a YouTube video URL."""
        return "watch?v=" in url or "youtu.be/" in url or "shorts/" in url

    def extract_video_id(self, url):
        """Extract video ID from a YouTube URL."""
        parsed_url = urlparse(url)
        if "youtu.be" in url:
            return parsed_url.path.lstrip('/').split('?')[0]
        elif "watch?v=" in url:
            return parse_qs(parsed_url.query).get("v", [None])[0]
        elif "shorts/" in url:
            return parsed_url.path.split("/shorts/")[1].split("?")[0]
        return None

    def download_audio(self, youtube_url, output_folder="downloads"):
        """Download audio from a YouTube video with unique filename."""
        try:
            video_id = self.extract_video_id(youtube_url)
            if not video_id:
                logger.error(f"Cannot download audio: invalid video ID for {youtube_url}")
                return None

            os.makedirs(output_folder, exist_ok=True)
            output_path = os.path.join(output_folder, f"audio_{video_id}.%(ext)s")
            ydl_opts = {
                "format": "bestaudio/best",
                "outtmpl": output_path,
            }
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(youtube_url, download=True)
                ext = info.get('ext', 'webm')
                audio_file = os.path.join(output_folder, f"audio_{video_id}.{ext}")
                if not os.path.exists(audio_file):
                    logger.error(f"Audio file not found: {audio_file}")
                    return None
                return audio_file
        except Exception as e:
            logger.error(f"Error downloading audio: {str(e)}")
            return None

    def transcribe_audio(self, audio_path):
        """Transcribe audio file to text using Whisper model."""
        try:
            model = WhisperModel("base", device="cpu")
            segments, _ = model.transcribe(audio_path)
            return "\n".join(segment.text for segment in segments)
        except Exception as e:
            logger.error(f"Error transcribing audio: {str(e)}")
            return None

    def get_latest_channel_videos(self, channel_url, video_count):
        """Fetch the latest N video URLs from a YouTube channel."""
        try:
            youtube = build('youtube', 'v3', developerKey=os.getenv("YOUTUBE_API_KEY"))
            parsed_url = urlparse(channel_url)
            path_parts = parsed_url.path.strip('/').split('/')
            known_suffixes = ['videos', 'shorts', 'featured', 'playlists', 'community', 'channels', 'about']

            if '@' in channel_url:
                for part in path_parts:
                    if part.startswith('@'):
                        handle = part.lstrip('@')
                        break
                else:
                    logger.error(f"No handle found in URL: {channel_url}")
                    return []

                if path_parts[-1] in known_suffixes:
                    path_parts = path_parts[:-1]

                logger.info(f"Fetching channel for handle: {handle}")
                channel_response = youtube.channels().list(
                    forHandle=handle,
                    part='id,contentDetails'
                ).execute()

                if not channel_response.get('items'):
                    logger.error(f"No channel found for handle: {handle}")
                    return []

                channel_id = channel_response['items'][0]['id']
                uploads_playlist_id = channel_response['items'][0]['contentDetails']['relatedPlaylists']['uploads']

            elif '/channel/' in channel_url:
                channel_id_index = path_parts.index('channel') + 1
                if channel_id_index < len(path_parts):
                    channel_id = path_parts[channel_id_index]
                else:
                    logger.error(f"Invalid channel URL format: {channel_url}")
                    return []

                logger.info(f"Fetching channel for ID: {channel_id}")
                channel_response = youtube.channels().list(
                    id=channel_id,
                    part='contentDetails'
                ).execute()

                if not channel_response.get('items'):
                    logger.error(f"No channel found for ID: {channel_id}")
                    return []

                uploads_playlist_id = channel_response['items'][0]['contentDetails']['relatedPlaylists']['uploads']

            elif '/user/' in channel_url:
                username_index = path_parts.index('user') + 1
                if username_index < len(path_parts):
                    username = path_parts[username_index]
                else:
                    logger.error(f"Invalid user URL format: {channel_url}")
                    return []

                logger.info(f"Fetching channel for username: {username}")
                channel_response = youtube.channels().list(
                    forUsername=username,
                    part='id,contentDetails'
                ).execute()

                if not channel_response.get('items'):
                    logger.error(f"No channel found for username: {username}")
                    return []

                channel_id = channel_response['items'][0]['id']
                uploads_playlist_id = channel_response['items'][0]['contentDetails']['relatedPlaylists']['uploads']

            else:
                logger.error(f"Invalid channel URL format: {channel_url}")
                return []

            playlist_response = youtube.playlistItems().list(
                playlistId=uploads_playlist_id,
                part='contentDetails',
                maxResults=video_count
            ).execute()

            video_urls = [
                f"https://www.youtube.com/watch?v={item['contentDetails']['videoId']}"
                for item in playlist_response.get('items', [])
            ]

            logger.info(f"Fetched video URLs: {video_urls}")
            return video_urls

        except Exception as e:
            logger.error(f"Error fetching channel videos: {str(e)}")
            return []

    def process_single_video(self, youtube_url, processed_video_ids, user, existing_transcripts, channel_url):
        """Process a single YouTube video: check database, download, transcribe, and store."""
        video_id = self.extract_video_id(youtube_url)
        if not video_id:
            logger.warning(f"Invalid video ID for URL: {youtube_url}")
            return None

        if video_id in processed_video_ids:
            logger.info(f"Skipping already processed video ID: {video_id}")
            return None

        # Check if video exists in database
        if video_id in existing_transcripts:
            transcript = existing_transcripts[video_id]
            return {
                'video_id': video_id,
                'video_url': youtube_url,
                'title': transcript.title,
                'status': transcript.status,
                'is_vector_stored': transcript.is_vector_stored,
                'channel_url': transcript.channel_url,
                'source': 'database',
                'error': 'Video has already been transcribed'
            }

        # Download audio
        audio_file = self.download_audio(youtube_url)
        if not audio_file:
            logger.error(f"Failed to download audio for {youtube_url}")
            with transaction.atomic():
                YouTubeTranscript.objects.create(
                    user=user,
                    video_id=video_id,
                    video_url=youtube_url,
                    status='failed',
                    is_vector_stored=False,
                    channel_url=channel_url,
                    processed_at=timezone.now()
                )
            return None

        # Get video title
        try:
            with yt_dlp.YoutubeDL({'quiet': True}) as ydl:
                info = ydl.extract_info(youtube_url, download=False)
                video_title = info.get('title', 'Untitled Video')
        except Exception:
            video_title = 'Untitled Video'

        # Transcribe audio
        transcript_content = self.transcribe_audio(audio_file)
        transcript_status = 'failed'
        is_vector_stored = False

        # Store in Pinecone if transcription succeeded
        if transcript_content:
            transcript_status = 'available'
            try:
                chunks = text_splitter.split_text(transcript_content)
                chunk_embeddings = embeddings.encode(chunks)
                vectors = [
                    {
                        'id': f"youtube_{video_id}_{i}",
                        'values': embedding.tolist(),
                        'metadata': {
                            'user_id': user.id,
                            'video_id': video_id,
                            'chunk_text': chunk,
                            'video_title': video_title,
                            'video_url': youtube_url,
                            'channel_url': channel_url or '',  # Use empty string if None
                            'source': 'youtube'
                        }
                    }
                    for i, (chunk, embedding) in enumerate(zip(chunks, chunk_embeddings))
                ]
                upsert_response = pinecone_index.upsert(vectors=vectors, async_req=True)
                upsert_response.get()
                logger.info(f"Stored {len(vectors)} transcript chunks in Pinecone for video {video_id}")
                is_vector_stored = True
            except Exception as e:
                logger.error(f"Failed to upsert to Pinecone for video {video_id}: {str(e)}")
                transcript_status = 'failed'

        # Store metadata in PostgreSQL
        with transaction.atomic():
            transcript_obj = YouTubeTranscript.objects.create(
                user=user,
                video_id=video_id,
                video_url=youtube_url,
                title=video_title,
                status=transcript_status,
                is_vector_stored=is_vector_stored,
                channel_url=channel_url,
                processed_at=timezone.now()
            )

        # Mark video as processed
        processed_video_ids.add(video_id)

        # Clean up audio file
        if audio_file and os.path.exists(audio_file):
            try:
                os.remove(audio_file)
            except Exception as e:
                logger.warning(f"Failed to delete audio file {audio_file}: {str(e)}")

        return {
            'video_id': video_id,
            'video_url': youtube_url,
            'title': video_title,
            'status': transcript_status,
            'is_vector_stored': is_vector_stored,
            'channel_url': channel_url,
            'source': 'api'
        }


class YouTubeTranscriptDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        """Delete a YouTube transcript from PostgreSQL and Pinecone."""
        try:
            video_id = request.data.get('video_id')
            if not video_id:
                return Response({'error': 'Video ID is required'}, status=400)

            user = request.user
            with transaction.atomic():
                try:
                    transcript = YouTubeTranscript.objects.get(user=user, video_id=video_id)
                except YouTubeTranscript.DoesNotExist:
                    return Response({'error': 'Transcript not found'}, status=404)

                # Delete from Pinecone if vectors exist
                if transcript.is_vector_stored:
                    try:
                        # Query Pinecone to find all vector IDs for this video
                        query_response = pinecone_index.query(
                            vector=[0] * 384,  # Dummy vector, we only need metadata
                            filter={'video_id': video_id, 'user_id': user.id},
                            top_k=1000,  # Assume max 1000 chunks
                            include_values=False
                        )
                        vector_ids = [match['id'] for match in query_response['matches']]
                        if vector_ids:
                            pinecone_index.delete(ids=vector_ids)
                            logger.info(f"Deleted {len(vector_ids)} vectors from Pinecone for video {video_id}")
                    except Exception as e:
                        logger.error(f"Failed to delete Pinecone vectors for video {video_id}: {str(e)}")
                        return Response({'error': f'Failed to delete from vector database: {str(e)}'}, status=500)

                # Delete from PostgreSQL
                transcript.delete()
                logger.info(f"Deleted YouTube transcript from PostgreSQL for video {video_id}")

            return Response({'message': 'YouTube transcript deleted successfully'}, status=200)

        except Exception as e:
            logger.error(f"Error deleting YouTube transcript: {str(e)}", exc_info=True)
            return Response({'error': f'Internal error: {str(e)}'}, status=500)


class WebsiteScraperView(APIView):
    def post(self, request):
        website_url = request.data.get("website_url")
        exclude = request.data.get("exclude", "").strip()

        if not website_url:
            return Response({'error': 'website_url is required'}, status=400)

        task = scrape_with_exclude.delay(website_url, exclude)
        return Response({'message': 'Scraping started', 'task_id': task.id}, status=202)


class TaskStatusView(APIView):
    def get(self, request, task_id):
        result = AsyncResult(task_id)

        if result.state == 'PENDING':
            return Response({"status": "Pending"}, status=202)
        elif result.state == 'STARTED':
            return Response({"status": "In Progress"}, status=202)
        elif result.state == 'SUCCESS':
            return Response({
                "status": "Completed",
                "result": result.result  # This will include all your scraped URLs + content
            }, status=200)
        elif result.state == 'FAILURE':
            return Response({
                "status": "Failed",
                "error": str(result.result)
            }, status=500)
        else:
            return Response({"status": result.state}, status=200)
        
