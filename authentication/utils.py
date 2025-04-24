import logging
from django.core.exceptions import ValidationError
from django.utils import timezone
from requests_oauthlib import OAuth2Session
import pytz

logger = logging.getLogger(__name__)

def refresh_oauth_token(token_obj, token_url, client_id, client_secret):
    token = {
        'access_token': token_obj.access_token,
        'refresh_token': token_obj.refresh_token,
        'expires_at': token_obj.expires_at.isoformat()
    }
    expires_at = token_obj.expires_at

    if expires_at.tzinfo is None:
        expires_at = pytz.UTC.localize(expires_at)

    oauth = OAuth2Session(client_id, token=token)
    if timezone.now() > expires_at:
        if not token_obj.refresh_token:
            raise ValidationError("Refresh token is missing. Re-authentication required.")
        
        try:
            new_token = oauth.refresh_token(
                token_url,
                client_id=client_id,
                client_secret=client_secret
            )
            token_obj.access_token = new_token['access_token']
            token_obj.refresh_token = new_token.get('refresh_token', token_obj.refresh_token)
            token_obj.expires_at = timezone.now() + timezone.timedelta(seconds=new_token['expires_in'])
            token_obj.save()
            oauth = OAuth2Session(client_id, token=new_token)
        except Exception as e:
            logger.error(f"Token refresh failed: {str(e)}")
            raise ValidationError(f"Token refresh failed: {str(e)}")
    return oauth

