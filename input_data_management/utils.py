import os
from moviepy.editor import VideoFileClip
from faster_whisper import WhisperModel
import logging
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
import tempfile
from . models import GoogleMeetTranscript
from django.db import transaction   
from .initializers import pinecone_index, embeddings, text_splitter
import re
from django.utils import timezone


logger = logging.getLogger(__name__)

GOOGLE_DRIVE_API = 'https://www.googleapis.com/drive/v3/files'


def generate_transcript_from_video(oauth, file_id, video_url):

    try:
        logger.info(f"Downloading video file with ID: {file_id}")
        video_response = oauth.get(f"{GOOGLE_DRIVE_API}/{file_id}?alt=media")
        if video_response.status_code != 200:
            logger.error(f"Failed to download video {file_id}: HTTP {video_response.status_code}")
            return f"Failed to download video: HTTP {video_response.status_code}"

        with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as tmp_video:
            tmp_video.write(video_response.content)
            tmp_video_path = tmp_video.name

        logger.info(f"Transcribing directly from video {file_id} using faster-whisper")
        model = WhisperModel("base", device="cpu", compute_type="int8")
        segments, _ = model.transcribe(tmp_video_path, beam_size=5)
        transcript = " ".join(segment.text for segment in segments).strip()

        if not transcript:
            logger.warning(f"No transcript generated for video {file_id}")
            return "No transcript generated"

        logger.info(f"Successfully generated transcript for video {file_id}")
        return transcript

    except Exception as e:
        logger.error(f"Error generating transcript for {file_id}: {str(e)}", exc_info=True)
        return f"Transcript generation failed: {str(e)}"

    finally:
        try:
            if 'tmp_video_path' in locals() and os.path.exists(tmp_video_path):
                os.remove(tmp_video_path)
                logger.info(f"Cleaned up {tmp_video_path}")
        except Exception as cleanup_error:
            logger.error(f"Failed to clean up temp file: {str(cleanup_error)}")


def get_meet_folder_id(oauth, user_id):
    """Fetch and cache the Meet Recordings folder ID."""
    cache_key = f"meet_folder_id_{user_id}"
    folder_id = cache.get(cache_key)
    if not folder_id:
        try:
            response = oauth.get(
                GOOGLE_DRIVE_API,
                params={
                    'q': "name='Meet Recordings' and mimeType='application/vnd.google-apps.folder'",
                    'fields': 'files(id)'
                }
            ).json()
            files = response.get('files', [])
            if not files:
                logger.warning(f"No 'Meet Recordings' folder found for user {user_id}")
                return None
            folder_id = files[0].get('id')
            if not folder_id:
                logger.warning(f"No valid folder ID in 'Meet Recordings' for user {user_id}")
                return None
            cache.set(cache_key, folder_id, timeout=3600)
        except Exception as e:
            cache.delete(cache_key)
            logger.error(f"Error fetching Meet Recordings folder for user {user_id}: {str(e)}")
            return None
    return folder_id

def process_single_recording(user, file_id, oauth, folder_id):
    try:
        logger.info(f"Processing recording {file_id} for user {user.id}")
        # Check if transcript already exists in PostgreSQL
        if GoogleMeetTranscript.objects.filter(user=user, file_id=file_id).exists():
            logger.info(f"Skipping recording {file_id} for user {user.id}: already processed")
            return

        # Check Pinecone for existing vectors
        fetch_response = pinecone_index.fetch(ids=[f"meet_{file_id}_0"])
        logger.info(f"Pinecone fetch response for ID meet_{file_id}_0: {fetch_response.vectors}")
        if fetch_response.vectors:
            logger.debug(f"Recording {file_id} already exists in Pinecone for user {user.id}")
            return

        video_response = oauth.get(
            f"{GOOGLE_DRIVE_API}/{file_id}",
            params={'fields': 'id,name,createdTime,webViewLink,size'}
        ).json()
        if 'error' in video_response:
            logger.error(f"Failed to fetch recording {file_id}: {video_response['error']}")
            return

        video_name = video_response['name']
        transcript_name = f"{video_name} - Transcript" if " - Recording" not in video_name else video_name.replace(" - Recording", " - Transcript")
        transcript_mime_types = [
            "text/plain", "application/vnd.google-apps.document", "text/vtt",
            "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "text/srt"
        ]
        mime_type_query = " or ".join([f"mimeType='{mime}'" for mime in transcript_mime_types])
        transcript_query = f"'{folder_id}' in parents and name='{transcript_name}' and ({mime_type_query})"
        transcript_response = oauth.get(
            GOOGLE_DRIVE_API,
            params={'q': transcript_query, 'fields': 'files(id,name,mimeType)'}
        ).json()
        transcript_files = transcript_response.get('files', [])
        transcript_file = transcript_files[0] if transcript_files else None
        transcript_content = ""
        transcript_status = "missing"
        is_vector_stored = False

        if transcript_file:
            transcript_file_id = transcript_file['id']
            mime_type = transcript_file['mimeType']
            logger.debug(f"Fetching transcript {transcript_file['name']} (ID: {transcript_file_id}, MIME: {mime_type})")
            if mime_type == "application/vnd.google-apps.document":
                export_url = f"{GOOGLE_DRIVE_API}/{transcript_file_id}/export"
                content_response = oauth.get(export_url, params={'mimeType': 'text/plain'})
                if content_response.status_code == 200:
                    transcript_content = clean_google_transcript(content_response.text)
                    transcript_status = "available"
                else:
                    logger.error(f"Failed to export Google Doc transcript {transcript_file_id}: {content_response.text}")
            elif mime_type in ["text/plain", "text/vtt", "text/srt"]:
                file_url = f"{GOOGLE_DRIVE_API}/{transcript_file_id}?alt=media"
                content_response = oauth.get(file_url)
                if content_response.status_code == 200:
                    transcript_content = clean_google_transcript(content_response.text)
                    transcript_status = "available"
                else:
                    logger.error(f"Failed to fetch transcript {transcript_file_id}: {content_response.text}")
        else:
            transcript_content = generate_transcript_from_video(oauth, file_id, video_response['webViewLink'])
            transcript_status = "generated" if transcript_content and "failed" not in transcript_content.lower() else "missing"

        # Store metadata in PostgreSQL
        with transaction.atomic():
            transcript_obj = GoogleMeetTranscript.objects.create(
                user=user,
                file_id=file_id,
                video_url=video_response['webViewLink'],
                processed_at=timezone.now(),
                status=transcript_status,
                source_name=video_name,
                created_time=video_response['createdTime'],
                file_size=video_response.get('size', 'Unknown'),
                is_vector_stored=False
            )
            logger.info(f"Saved metadata for recording {file_id} to relational DB with status {transcript_status}")

        # Store transcript in Pinecone if available
        if transcript_content:
            try:
                chunks = text_splitter.split_text(transcript_content)
                chunk_embeddings = embeddings.encode(chunks, convert_to_numpy=True)
                vectors = [
                    {
                        'id': f"meet_{file_id}_{i}",
                        'values': embedding.tolist(),
                        'metadata': {
                            'user_id': user.id,
                            'file_id': file_id,
                            'chunk_text': chunk,
                            'recording_name': video_name,
                            'video_url': video_response['webViewLink'],
                            'created_time': video_response['createdTime'],
                            'source': 'google_meet'
                        }
                    }
                    for i, (chunk, embedding) in enumerate(zip(chunks, chunk_embeddings))
                ]
                upsert_response = pinecone_index.upsert(vectors=vectors, async_req=True)
                upsert_response.get()
                logger.info(f"Stored {len(vectors)} transcript chunks in Pinecone for recording {file_id}")
                transcript_obj.is_vector_stored = True
                transcript_obj.save()
                is_vector_stored = True
            except Exception as e:
                logger.error(f"Failed to upsert to Pinecone for recording {file_id}: {str(e)}", exc_info=True)
                transcript_obj.status = 'failed'
                transcript_obj.save()
                raise

    except Exception as e:
        logger.error(f"Error processing recording {file_id} for user {user.id}: {str(e)}", exc_info=True)
        if 'transcript_obj' in locals():
            transcript_obj.status = 'failed'
            transcript_obj.save()


def clean_google_transcript(text):
    if not text:
        return ""
    text = text.replace('\ufeff', '').replace('ï»¿', '').strip()
    last_index = text.rfind("Meeting ended after")
    if last_index != -1:
        text = text[:last_index].strip()
    lines = text.splitlines()
    cleaned_lines = []
    for line in lines:
        line = line.strip()
        if (re.match(r'.* - Transcript$', line) or 
            line == 'Attendees' or 
            line == 'Transcript' or 
            not line):
            continue
        if ':' not in line and line in [l.split(':')[0].strip() for l in lines if ':' in l]:
            continue
        cleaned_lines.append(line)
    return '\n'.join(cleaned_lines)

def clean_zoom_transcript(text):
    lines = text.splitlines()
    cleaned_lines = []
    for line in lines:
        if (line.strip() == 'WEBVTT' or 
            not line.strip() or 
            re.match(r'^\d+$', line.strip()) or 
            re.match(r'^\d{2}:\d{2}:\d{2}\.\d{3} --> \d{2}:\d{2}:\d{2}\.\d{3}$', line.strip())):
            continue
        cleaned_lines.append(line.strip())
    return '\n'.join(cleaned_lines)

def clean_teams_transcript(vtt_text: str) -> str:
    vtt_text = re.sub(r"\d{2}:\d{2}:\d{2}\.\d{3} --> \d{2}:\d{2}:\d{2}\.\d{3}", "", vtt_text)
    cleaned_lines = []
    for line in vtt_text.splitlines():
        match = re.match(r"<v (.*?)>(.*?)</v>", line)
        if match:
            speaker, text = match.groups()
            cleaned_lines.append(f"{speaker}: {text.strip()}")
    return "\n".join(cleaned_lines)