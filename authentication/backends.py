import jwt
from django.contrib.auth.models import User
from django.core.cache import cache
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.conf import settings
import requests
from jwt.algorithms import RSAAlgorithm

class ClerkJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return None

        try:
            token = auth_header.split(" ")[1]
        except IndexError:
            raise AuthenticationFailed("Bearer token not provided.")

        try:
            # Fetch JWKS from Clerk
            jwks_data = cache.get('clerk_jwks')
            if not jwks_data:
                response = requests.get(f"{settings.CLERK_FRONTEND_API_URL}/.well-known/jwks.json")
                if response.status_code != 200:
                    raise AuthenticationFailed("Failed to fetch JWKS.")
                jwks_data = response.json()
                cache.set('clerk_jwks', jwks_data, timeout=86400)  # Cache for 24 hours

            public_key = RSAAlgorithm.from_jwk(jwks_data["keys"][0])
            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                options={"verify_signature": True},
            )

            user_id = payload.get("sub")
            session_id = payload.get("sid")
            if not user_id or not session_id:
                raise AuthenticationFailed("Invalid token payload.")

            try:
                user = User.objects.get(username=user_id)
                return user, token
            except User.DoesNotExist:
                raise AuthenticationFailed("User not found. Please ensure user is synced via webhook.")

        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Token has expired.")
        except jwt.DecodeError:
            raise AuthenticationFailed("Token decode error.")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token.")
        except Exception as e:
            raise AuthenticationFailed(f"Authentication failed: {str(e)}")