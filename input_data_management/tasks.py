from celery import shared_task
from django.contrib.auth.models import User
from django.conf import settings
from .models import GoogleDriveWebhook, GoogleMeetTranscript
from authentication.models import GoogleToken
from .utils import get_meet_folder_id
from .utils import process_single_recording
from authentication.utils import refresh_oauth_token
import logging
from pinecone.exceptions import PineconeException
from requests.exceptions import RequestException
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import uuid
from django.utils import timezone
import pinecone  # Import to check version
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import os, httpx, pendulum
import asyncio
import re
SCRAPER_API_URL = "http://api.scraperapi.com"


logger = logging.getLogger(__name__)

GOOGLE_DRIVE_API = 'https://www.googleapis.com/drive/v3/files'

@shared_task(bind=True, max_retries=3)
def process_new_recording(self, user_id, file_id):
    logger.info(f"Starting process_new_recording for user {user_id}, file {file_id}")
    try:
        user = User.objects.get(id=user_id)
        token_obj = GoogleToken.objects.get(user=user)
        oauth = refresh_oauth_token(
            token_obj, 'https://oauth2.googleapis.com/token',
            settings.GOOGLE_CLIENT_ID, settings.GOOGLE_CLIENT_SECRET
        )

        folder_id = get_meet_folder_id(oauth, user.id)
        if not folder_id:
            logger.error(f"Meet Recordings folder not found for user {user.id}")
            return

        process_single_recording(user, file_id, oauth, folder_id)
    except (PineconeException, RequestException) as e:
        logger.error(f"Transient error in Celery task for user {user_id}, file {file_id}: {str(e)}")
        self.retry(countdown=60, exc=e)
    except Exception as e:
        logger.error(f"Permanent error in Celery task for user {user_id}, file {file_id}: {str(e)}", exc_info=True)
        raise


@shared_task
def poll_google_recordings(user_id):
    logger.info(f"Starting poll_google_recordings for user {user_id}")
    try:
        user = User.objects.get(id=user_id)
        # if GoogleDriveWebhook.objects.filter(
        #     user=user,
        #     created_at__gte=timezone.now() - timezone.timedelta(days=6)
        # ).exists():
        #     logger.info(f"Skipping polling for user {user.id} with active webhook")
        #     return

        token_obj = GoogleToken.objects.get(user=user)
        oauth = refresh_oauth_token(
            token_obj, 'https://oauth2.googleapis.com/token',
            settings.GOOGLE_CLIENT_ID, settings.GOOGLE_CLIENT_SECRET
        )

        folder_id = get_meet_folder_id(oauth, user.id)
        if not folder_id:
            logger.error(f"Meet Recordings folder not found for user {user.id}")
            return

        video_query = f"'{folder_id}' in parents and mimeType contains 'video/'"
        video_response = oauth.get(
            GOOGLE_DRIVE_API,
            params={
                'q': video_query,
                'fields': 'files(id)',
                'orderBy': 'createdTime desc',
                'pageSize': 10
            }
        ).json()
        recordings = video_response.get('files', [])

        # Check PostgreSQL for existing transcripts
        existing_file_ids = set(
            GoogleMeetTranscript.objects.filter(user=user).values_list('file_id', flat=True)
        )
        logger.info(f"Found existing file IDs in PostgreSQL: {existing_file_ids}")

        for rec in recordings:
            file_id = rec['id']
            if file_id not in existing_file_ids:
                logger.info(f"Polling detected new recording {file_id} for user {user.id}")
                process_new_recording.delay(user.id, file_id)
            else:
                logger.info(f"Skipping recording {file_id} for user {user.id}: already in PostgreSQL")

    except Exception as e:
        logger.error(f"Error polling recordings for user {user_id}: {str(e)}", exc_info=True)
        raise


@shared_task
def poll_all_users():
    logger.info("Starting poll_all_users")
    try:
        google_tokens = GoogleToken.objects.all()
        logger.info(f"Found {google_tokens.count()} Google tokens")
        for token in google_tokens:
            user_id = token.user.id
            logger.info(f"Scheduling poll for user {user_id}")
            poll_google_recordings.delay(user_id)
    except Exception as e:
        logger.error(f"Error scheduling polling for users: {str(e)}", exc_info=True)


@shared_task
def renew_webhook(channel_id):
    logger.info(f"Starting renew_webhook for channel {channel_id}")
    try:
        webhook = GoogleDriveWebhook.objects.get(channel_id=channel_id)
        user = webhook.user
        token_obj = GoogleToken.objects.get(user=user)
        creds = Credentials(
            token=token_obj.access_token,
            refresh_token=token_obj.refresh_token,
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET,
            token_uri='https://oauth2.googleapis.com/token'
        )
        drive = build('drive', 'v3', credentials=creds)

        drive.channels().stop(body={
            'id': webhook.channel_id,
            'resourceId': webhook.resource_id
        }).execute()

        folder_id = get_meet_folder_id(creds, user.id)
        if not folder_id:
            logger.error(f"Meet Recordings folder not found for user {user.id}")
            return

        new_channel_id = str(uuid.uuid4())
        new_channel_token = str(uuid.uuid4())
        webhook_url = settings.WEBHOOK_URL
        response = drive.changes().watch(
            pageToken=webhook.last_page_token,
            body={
                'id': new_channel_id,
                'type': 'web_hook',
                'address': webhook_url,
                'token': new_channel_token
            }
        ).execute()

        webhook.channel_id = new_channel_id
        webhook.resource_id = response['resourceId']
        webhook.channel_token = new_channel_token
        webhook.created_at = timezone.now()
        webhook.save()
        logger.info(f"Renewed webhook for user {user.id}, new channel_id={new_channel_id}")
    except Exception as e:
        logger.error(f"Error renewing webhook {channel_id}: {str(e)}", exc_info=True)


# @shared_task
# def scrape_with_exclude(website_url, exclude_keyword):
#     visited = set()
#     to_scrape = [website_url]
#     result = []

#     logger.info(f"[TASK STARTED] Scraping initiated for {website_url} with exclude = {exclude_keyword}")

#     async def fetch_page(client, url):
#         try:
#             logger.info(f"[FETCHING] URL: {url}")
#             params = {'api_key': os.getenv('SCRAPER_API_KEY'), 'url': url}
#             resp = await client.get(SCRAPER_API_URL, params=params)
#             if resp.status_code == 200:
#                 soup = BeautifulSoup(resp.text, 'html.parser')
#                 text = soup.get_text(strip=True)
#                 links = {
#                     urljoin(url, a['href']) for a in soup.find_all('a', href=True)
#                     if urlparse(urljoin(url, a['href'])).netloc == urlparse(website_url).netloc
#                 }
#                 logger.info(f"[PARSED] {url} | {len(links)} internal links")
#                 return url, text, links
#             else:
#                 logger.warning(f"[SKIPPED] {url} | Status Code: {resp.status_code}")
#         except Exception as e:
#             logger.error(f"[ERROR] Fetching {url} failed: {str(e)}")
#         return url, None, set()

#     async def run_scrape():
#         async with httpx.AsyncClient() as client:
#             nonlocal to_scrape
#             while to_scrape and len(visited) < 100:
#                 current_batch = to_scrape[:100 - len(visited)]
#                 to_scrape = to_scrape[len(current_batch):]

#                 responses = await asyncio.gather(
#                     *[fetch_page(client, link) for link in current_batch]
#                 )

#                 for url, text, links in responses:
#                     if url and url not in visited and text:
#                         if exclude_keyword and exclude_keyword in url:
#                             logger.info(f"[EXCLUDED] Skipping {url} due to keyword '{exclude_keyword}'")
#                             continue
#                         visited.add(url)
#                         result.append({
#                             'url': url,
#                             'text_content': text,
#                             'internal_links': list(links),
#                             'scraped_at': pendulum.now('UTC').to_iso8601_string()
#                         })
#                         logger.info(f"[SCRAPED] {url} | Total Scraped: {len(result)}")

#                         for link in links:
#                             if link not in visited and exclude_keyword not in link:
#                                 to_scrape.append(link)
#         return result

#     try:
#         final_result = asyncio.run(run_scrape())
#         logger.info(f"[TASK COMPLETED] Total pages scraped: {len(final_result)}")
#         return final_result
#     except Exception as e:
#         logger.exception(f"[TASK ERROR] {str(e)}")
#         return []

# @shared_task
# def scrape_with_exclude(website_url, exclude_keyword):
#     visited = set()
#     to_scrape = [(website_url, 0)]  # (url, depth)
#     result = []

#     logger.info(f"[TASK STARTED] Scraping initiated for {website_url} with exclude = {exclude_keyword}")

#     # Normalize exclude_keyword for flexible matching
#     exclude_pattern = None
#     if exclude_keyword:
#         # Escape special characters and handle partial URLs/keywords
#         exclude_keyword = re.escape(exclude_keyword.strip('/')).replace(r'\/', '/')
#         exclude_pattern = re.compile(exclude_keyword, re.IGNORECASE)

#     async def fetch_page(client, url):
#         try:
#             logger.info(f"[FETCHING] URL: {url}")
#             params = {'api_key': os.getenv('SCRAPER_API_KEY'), 'url': url}
#             resp = await client.get(SCRAPER_API_URL, params=params)
#             if resp.status_code == 200:
#                 soup = BeautifulSoup(resp.text, 'html.parser')
#                 text = soup.get_text(strip=True)
#                 links = {
#                     urljoin(url, a['href']) for a in soup.find_all('a', href=True)
#                     if urlparse(urljoin(url, a['href'])).netloc == urlparse(website_url).netloc
#                 }
#                 logger.info(f"[PARSED] {url} | {len(links)} internal links")
#                 return url, text, links
#             else:
#                 logger.warning(f"[SKIPPED] {url} | Status Code: {resp.status_code}")
#         except Exception as e:
#             logger.error(f"[ERROR] Fetching {url} failed: {str(e)}")
#         return url, None, set()

#     async def run_scrape():
#         async with httpx.AsyncClient() as client:
#             nonlocal to_scrape
#             while to_scrape and len(visited) < 100:
#                 current_batch = to_scrape[:100 - len(visited)]
#                 to_scrape = to_scrape[len(current_batch):]

#                 responses = await asyncio.gather(
#                     *[fetch_page(client, url) for url, _ in current_batch]
#                 )

#                 for url, text, links in responses:
#                     if url and url not in visited and text:
#                         if exclude_pattern and exclude_pattern.search(url):
#                             logger.info(f"[EXCLUDED] Skipping {url} due to keyword '{exclude_keyword}'")
#                             continue
#                         visited.add(url)
#                         depth = next(d for u, d in current_batch if u == url)
#                         result.append({
#                             'url': url,
#                             'text_content': text,
#                             'internal_links': list(links),
#                             'depth': depth,
#                             'scraped_at': pendulum.now('UTC').to_iso8601_string()
#                         })
#                         logger.info(f"[SCRAPED] {url} | Depth: {depth} | Total Scraped: {len(result)}")

#                         if depth < 2:  # Only add links if depth < 2
#                             for link in links:
#                                 if link not in visited and (not exclude_pattern or not exclude_pattern.search(link)):
#                                     to_scrape.append((link, depth + 1))
#         return result

#     try:
#         final_result = asyncio.run(run_scrape())
#         logger.info(f"[TASK COMPLETED] Total pages scraped: {len(final_result)}")
#         return final_result
#     except Exception as e:
#         logger.exception(f"[TASK ERROR] {str(e)}")
#         return []

@shared_task
def scrape_with_exclude(website_url, exclude_keyword):
    visited = set()
    to_scrape = [(website_url, 0)]  # (url, depth)
    result = []

    logger.info(f"[TASK STARTED] Scraping initiated for {website_url} with exclude = {exclude_keyword}")

    # Normalize exclude_keyword for flexible matching
    exclude_pattern = None
    if exclude_keyword:
        exclude_keyword = re.escape(exclude_keyword.strip('/')).replace(r'\/', '/')
        exclude_pattern = re.compile(exclude_keyword, re.IGNORECASE)

    async def fetch_page(client, url):
        try:
            logger.info(f"[FETCHING] URL: {url}")
            params = {'api_key': os.getenv('SCRAPER_API_KEY'), 'url': url}
            async with client.stream('GET', SCRAPER_API_URL, params=params, timeout=30) as resp:
                if resp.status_code == 200:
                    await resp.aread()  # Read the streaming response
                    text = resp.text
                    soup = BeautifulSoup(text, 'html.parser')
                    text_content = soup.get_text(strip=True)
                    links = {
                        urljoin(url, a['href']) for a in soup.find_all('a', href=True)
                        if urlparse(urljoin(url, a['href'])).netloc == urlparse(website_url).netloc
                    }
                    logger.info(f"[PARSED] {url} | {len(links)} internal links")
                    return url, text_content, links
                else:
                    logger.warning(f"[SKIPPED] {url} | Status Code: {resp.status_code}")
        except Exception as e:
            logger.error(f"[ERROR] Fetching {url} failed: {type(e).__name__}: {str(e)}")
        return url, None, set()

    async def run_scrape():
        async with httpx.AsyncClient() as client:
            nonlocal to_scrape
            while to_scrape and len(visited) < 100:
                current_batch = to_scrape[:100 - len(visited)]
                to_scrape = to_scrape[len(current_batch):]

                responses = await asyncio.gather(
                    *[fetch_page(client, url) for url, depth in current_batch],
                    return_exceptions=True
                )

                for response in responses:
                    if isinstance(response, Exception):
                        logger.error(f"[ERROR] Async gather failed: {str(response)}")
                        continue
                    url, text, links = response
                    if url and url not in visited and text:
                        if exclude_pattern and exclude_pattern.search(url):
                            logger.info(f"[EXCLUDED] Skipping {url} due to keyword '{exclude_keyword}'")
                            continue
                        visited.add(url)
                        depth = next(d for u, d in current_batch if u == url)
                        result.append({
                            'url': url,
                            'text_content': text,
                            'internal_links': list(links),
                            'depth': depth,
                            'scraped_at': pendulum.now('UTC').to_iso8601_string()
                        })
                        logger.info(f"[SCRAPED] {url} | Depth: {depth} | Total Scraped: {len(result)}")

                        if depth < 2:
                            for link in links:
                                if link not in visited and (not exclude_pattern or not exclude_pattern.search(link)):
                                    to_scrape.append((link, depth + 1))
        return result

    try:
        final_result = asyncio.run(run_scrape())
        logger.info(f"[TASK COMPLETED] Total pages scraped: {len(final_result)}")
        return final_result
    except Exception as e:
        logger.exception(f"[TASK ERROR] {type(e).__name__}: {str(e)}")
        return []