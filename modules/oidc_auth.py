"""
OIDC/SSO Authentication Module for Synapse
Handles OpenID Connect authentication with multiple providers
"""

import logging
import aiohttp
import jwt
from typing import Dict, Any, Optional
from urllib.parse import urlencode, parse_qs
import secrets
import time

from synapse.module_api import ModuleApi

logger = logging.getLogger(__name__)


class OIDCAuthModule:
    def __init__(self, config: Dict[str, Any], api: ModuleApi):
        self.api = api
        self.config = config
        self.providers = config.get("providers", {})
        self.redirect_uri = config.get("redirect_uri", "http://localhost:8008/_matrix/client/r0/login/sso/redirect")
        
        # Store state for CSRF protection
        self.state_store = {}
        
        logger.info(f"OIDCAuthModule initialized with {len(self.providers)} providers")

    def generate_state(self, provider_id: str) -> str:
        """
        Generate a random state parameter for CSRF protection
        """
        state = secrets.token_urlsafe(32)
        self.state_store[state] = {
            "provider_id": provider_id,
            "created_at": time.time(),
            "used": False
        }
        return state

    def validate_state(self, state: str) -> Optional[str]:
        """
        Validate state parameter and return provider ID
        """
        if state not in self.state_store:
            return None
        
        state_data = self.state_store[state]
        
        # Check if state has expired (5 minutes)
        if time.time() - state_data["created_at"] > 300:
            del self.state_store[state]
            return None
        
        # Check if state has already been used
        if state_data["used"]:
            return None
        
        # Mark state as used
        state_data["used"] = True
        
        return state_data["provider_id"]

    def get_authorization_url(self, provider_id: str) -> Optional[str]:
        """
        Get the authorization URL for the specified provider
        """
        if provider_id not in self.providers:
            return None
        
        provider = self.providers[provider_id]
        state = self.generate_state(provider_id)
        
        params = {
            "client_id": provider["client_id"],
            "response_type": "code",
            "scope": " ".join(provider.get("scopes", ["openid", "profile", "email"])),
            "redirect_uri": self.redirect_uri,
            "state": state,
            "nonce": secrets.token_urlsafe(16)
        }
        
        # Add provider-specific parameters
        if "additional_params" in provider:
            params.update(provider["additional_params"])
        
        auth_url = provider["authorization_endpoint"] + "?" + urlencode(params)
        return auth_url

    async def exchange_code_for_token(self, provider_id: str, code: str) -> Optional[Dict[str, Any]]:
        """
        Exchange authorization code for access token
        """
        if provider_id not in self.providers:
            return None
        
        provider = self.providers[provider_id]
        
        token_data = {
            "grant_type": "authorization_code",
            "client_id": provider["client_id"],
            "client_secret": provider["client_secret"],
            "code": code,
            "redirect_uri": self.redirect_uri
        }
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    provider["token_endpoint"],
                    data=token_data,
                    headers=headers
                ) as response:
                    if response.status == 200:
                        token_response = await response.json()
                        return token_response
                    else:
                        logger.error(f"Token exchange failed: {response.status}")
                        return None
        except Exception as e:
            logger.error(f"Error exchanging code for token: {e}")
            return None

    async def get_user_info(self, provider_id: str, access_token: str) -> Optional[Dict[str, Any]]:
        """
        Get user information from the provider
        """
        if provider_id not in self.providers:
            return None
        
        provider = self.providers[provider_id]
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    provider["userinfo_endpoint"],
                    headers=headers
                ) as response:
                    if response.status == 200:
                        user_info = await response.json()
                        return user_info
                    else:
                        logger.error(f"Failed to get user info: {response.status}")
                        return None
        except Exception as e:
            logger.error(f"Error getting user info: {e}")
            return None

    def map_user_info_to_matrix_user(self, provider_id: str, user_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map provider user info to Matrix user format
        """
        # Default mapping
        matrix_user = {
            "user_id": None,
            "display_name": user_info.get("name", ""),
            "avatar_url": user_info.get("picture", ""),
            "email": user_info.get("email", ""),
            "provider": provider_id
        }
        
        # Provider-specific mapping
        if provider_id == "google":
            matrix_user["user_id"] = f"@{user_info.get('sub', '')}:localhost"
            matrix_user["display_name"] = user_info.get("name", "")
            matrix_user["email"] = user_info.get("email", "")
            
        elif provider_id == "github":
            matrix_user["user_id"] = f"@{user_info.get('login', '')}:localhost"
            matrix_user["display_name"] = user_info.get("name", user_info.get("login", ""))
            matrix_user["email"] = user_info.get("email", "")
            
        elif provider_id == "microsoft":
            matrix_user["user_id"] = f"@{user_info.get('sub', '')}:localhost"
            matrix_user["display_name"] = user_info.get("displayName", "")
            matrix_user["email"] = user_info.get("mail", user_info.get("userPrincipalName", ""))
        
        return matrix_user

    async def create_or_get_matrix_user(self, matrix_user: Dict[str, Any]) -> Optional[str]:
        """
        Create or get existing Matrix user
        """
        try:
            user_id = matrix_user["user_id"]
            
            # Check if user exists
            existing_user = await self.api.get_user_by_id(user_id)
            if existing_user:
                return user_id
            
            # Create new user
            # In production, you would use the proper Synapse API
            # For demo purposes, we'll return the user ID
            logger.info(f"Created new Matrix user: {user_id}")
            return user_id
            
        except Exception as e:
            logger.error(f"Error creating Matrix user: {e}")
            return None

    async def handle_oidc_callback(self, provider_id: str, code: str, state: str) -> Optional[Dict[str, Any]]:
        """
        Handle OIDC callback and complete authentication
        """
        try:
            # Validate state
            validated_provider = self.validate_state(state)
            if not validated_provider or validated_provider != provider_id:
                logger.error("Invalid state parameter")
                return None
            
            # Exchange code for token
            token_response = await self.exchange_code_for_token(provider_id, code)
            if not token_response:
                logger.error("Failed to exchange code for token")
                return None
            
            access_token = token_response.get("access_token")
            if not access_token:
                logger.error("No access token in response")
                return None
            
            # Get user info
            user_info = await self.get_user_info(provider_id, access_token)
            if not user_info:
                logger.error("Failed to get user info")
                return None
            
            # Map to Matrix user format
            matrix_user = self.map_user_info_to_matrix_user(provider_id, user_info)
            
            # Create or get Matrix user
            user_id = await self.create_or_get_matrix_user(matrix_user)
            if not user_id:
                logger.error("Failed to create Matrix user")
                return None
            
            # Generate Matrix access token
            matrix_token = self.generate_matrix_token(user_id)
            
            return {
                "user_id": user_id,
                "access_token": matrix_token,
                "display_name": matrix_user["display_name"],
                "avatar_url": matrix_user["avatar_url"],
                "provider": provider_id
            }
            
        except Exception as e:
            logger.error(f"Error in OIDC callback: {e}")
            return None

    def generate_matrix_token(self, user_id: str) -> str:
        """
        Generate a Matrix access token for the user
        """
        # In production, you would use the proper Synapse token generation
        # For demo purposes, we'll generate a simple token
        import hashlib
        import time
        
        token_data = f"{user_id}:{time.time()}:{secrets.token_urlsafe(16)}"
        token = hashlib.sha256(token_data.encode()).hexdigest()
        return token

    def get_provider_info(self, provider_id: str) -> Optional[Dict[str, Any]]:
        """
        Get provider information for frontend
        """
        if provider_id not in self.providers:
            return None
        
        provider = self.providers[provider_id]
        return {
            "id": provider_id,
            "name": provider.get("name", provider_id.title()),
            "icon": provider.get("icon", ""),
            "auth_url": self.get_authorization_url(provider_id)
        }

    def get_available_providers(self) -> List[Dict[str, Any]]:
        """
        Get list of available OIDC providers
        """
        providers = []
        for provider_id in self.providers:
            provider_info = self.get_provider_info(provider_id)
            if provider_info:
                providers.append(provider_info)
        return providers


def create_module(config: Dict[str, Any], api: ModuleApi):
    return OIDCAuthModule(config, api)
