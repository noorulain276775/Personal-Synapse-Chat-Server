"""
Advanced Authentication Manager for Synapse
Handles multiple authentication methods, user management, and security policies
"""

import logging
import hashlib
import secrets
import time
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import jwt
import bcrypt
import re

from synapse.module_api import ModuleApi

logger = logging.getLogger(__name__)


class AuthManagerModule:
    def __init__(self, config: Dict[str, Any], api: ModuleApi):
        self.api = api
        self.config = config
        
        # Authentication settings
        self.password_policy = config.get("password_policy", {})
        self.jwt_secret = config.get("jwt_secret", "default-secret-change-me")
        self.session_timeout = config.get("session_timeout", 1800)  # 30 minutes
        self.max_login_attempts = config.get("max_login_attempts", 5)
        self.lockout_duration = config.get("lockout_duration", 900)  # 15 minutes
        
        # In-memory storage for demo (use Redis in production)
        self.failed_attempts = {}
        self.user_sessions = {}
        self.password_history = {}
        
        logger.info("AuthManagerModule initialized")
        
        # Register authentication callbacks
        self.api.register_password_auth_provider_callbacks(
            check_password=self.check_password,
            check_3pid_auth=self.check_3pid_auth,
            on_logout=self.on_logout
        )

    def validate_password_strength(self, password: str, user_id: str) -> Dict[str, Any]:
        """
        Validate password against security policy
        """
        errors = []
        
        # Check minimum length
        min_length = self.password_policy.get("minimum_length", 8)
        if len(password) < min_length:
            errors.append(f"Password must be at least {min_length} characters long")
        
        # Check for required character types
        if self.password_policy.get("require_digit", True):
            if not re.search(r'\d', password):
                errors.append("Password must contain at least one digit")
        
        if self.password_policy.get("require_lowercase", True):
            if not re.search(r'[a-z]', password):
                errors.append("Password must contain at least one lowercase letter")
        
        if self.password_policy.get("require_uppercase", True):
            if not re.search(r'[A-Z]', password):
                errors.append("Password must contain at least one uppercase letter")
        
        if self.password_policy.get("require_symbol", True):
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                errors.append("Password must contain at least one special character")
        
        # Check against common passwords
        if self.password_policy.get("require_non_common", True):
            common_passwords = ["password", "123456", "admin", "qwerty", "letmein"]
            if password.lower() in common_passwords:
                errors.append("Password cannot be a common password")
        
        # Check password history
        if user_id in self.password_history:
            for old_hash in self.password_history[user_id][-5:]:  # Last 5 passwords
                if bcrypt.checkpw(password.encode(), old_hash.encode()):
                    errors.append("Password cannot be the same as your last 5 passwords")
                    break
        
        # Calculate entropy
        min_entropy = self.password_policy.get("min_entropy", 0.5)
        entropy = self.calculate_entropy(password)
        if entropy < min_entropy:
            errors.append(f"Password entropy too low (minimum: {min_entropy})")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "entropy": entropy
        }

    def calculate_entropy(self, password: str) -> float:
        """
        Calculate password entropy
        """
        char_set_size = 0
        if re.search(r'[a-z]', password):
            char_set_size += 26
        if re.search(r'[A-Z]', password):
            char_set_size += 26
        if re.search(r'\d', password):
            char_set_size += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            char_set_size += 32
        
        if char_set_size == 0:
            return 0
        
        return len(password) * (char_set_size ** 0.5) / 100

    def is_user_locked_out(self, user_id: str) -> bool:
        """
        Check if user is locked out due to failed attempts
        """
        if user_id not in self.failed_attempts:
            return False
        
        attempts = self.failed_attempts[user_id]
        if attempts["count"] >= self.max_login_attempts:
            lockout_time = attempts["last_attempt"] + self.lockout_duration
            if time.time() < lockout_time:
                return True
            else:
                # Reset failed attempts after lockout period
                del self.failed_attempts[user_id]
        
        return False

    def record_failed_attempt(self, user_id: str):
        """
        Record a failed login attempt
        """
        if user_id not in self.failed_attempts:
            self.failed_attempts[user_id] = {"count": 0, "last_attempt": 0}
        
        self.failed_attempts[user_id]["count"] += 1
        self.failed_attempts[user_id]["last_attempt"] = time.time()
        
        logger.warning(f"Failed login attempt for user {user_id} (attempt {self.failed_attempts[user_id]['count']})")

    def clear_failed_attempts(self, user_id: str):
        """
        Clear failed attempts for successful login
        """
        if user_id in self.failed_attempts:
            del self.failed_attempts[user_id]

    def create_session(self, user_id: str) -> str:
        """
        Create a new user session
        """
        session_id = secrets.token_urlsafe(32)
        self.user_sessions[session_id] = {
            "user_id": user_id,
            "created_at": time.time(),
            "last_activity": time.time(),
            "ip_address": None  # Would be set from request context
        }
        
        logger.info(f"Created session {session_id} for user {user_id}")
        return session_id

    def validate_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Validate a user session
        """
        if session_id not in self.user_sessions:
            return None
        
        session = self.user_sessions[session_id]
        current_time = time.time()
        
        # Check if session has expired
        if current_time - session["last_activity"] > self.session_timeout:
            del self.user_sessions[session_id]
            return None
        
        # Update last activity
        session["last_activity"] = current_time
        return session

    def generate_jwt_token(self, user_id: str, additional_claims: Dict[str, Any] = None) -> str:
        """
        Generate a JWT token for the user
        """
        now = datetime.utcnow()
        payload = {
            "user_id": user_id,
            "iat": now,
            "exp": now + timedelta(hours=24),
            "iss": "matrix-synapse",
            "aud": "matrix-client"
        }
        
        if additional_claims:
            payload.update(additional_claims)
        
        token = jwt.encode(payload, self.jwt_secret, algorithm="HS256")
        return token

    def validate_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate a JWT token
        """
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid JWT token")
            return None

    async def check_password(self, user_id: str, password: str) -> bool:
        """
        Check user password and handle authentication
        """
        try:
            # Check if user is locked out
            if self.is_user_locked_out(user_id):
                logger.warning(f"Login attempt for locked out user {user_id}")
                return False
            
            # Get user from database (simplified for demo)
            # In production, you would query the actual user database
            user = await self.get_user_by_id(user_id)
            if not user:
                logger.warning(f"User {user_id} not found")
                return False
            
            # Verify password
            if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
                self.record_failed_attempt(user_id)
                return False
            
            # Clear failed attempts on successful login
            self.clear_failed_attempts(user_id)
            
            # Create session
            session_id = self.create_session(user_id)
            
            logger.info(f"Successful login for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error in password check: {e}")
            return False

    async def check_3pid_auth(self, medium: str, address: str, password: str) -> Optional[str]:
        """
        Check third-party identifier authentication (email, phone)
        """
        try:
            # This would typically involve checking against external identity providers
            # For demo purposes, we'll implement a simple email check
            if medium == "email":
                user_id = await self.get_user_by_email(address)
                if user_id and await self.check_password(user_id, password):
                    return user_id
            
            return None
            
        except Exception as e:
            logger.error(f"Error in 3PID auth: {e}")
            return None

    async def on_logout(self, user_id: str, device_id: str, access_token: str):
        """
        Handle user logout
        """
        try:
            # Remove session from memory
            sessions_to_remove = []
            for session_id, session in self.user_sessions.items():
                if session["user_id"] == user_id:
                    sessions_to_remove.append(session_id)
            
            for session_id in sessions_to_remove:
                del self.user_sessions[session_id]
            
            logger.info(f"User {user_id} logged out")
            
        except Exception as e:
            logger.error(f"Error in logout handler: {e}")

    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user by ID (simplified for demo)
        """
        # In production, this would query the actual database
        # For demo purposes, we'll return a mock user
        return {
            "user_id": user_id,
            "password_hash": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HSKzKqK",  # "password123"
            "email": f"{user_id}@localhost",
            "created_at": time.time()
        }

    async def get_user_by_email(self, email: str) -> Optional[str]:
        """
        Get user ID by email (simplified for demo)
        """
        # In production, this would query the actual database
        # For demo purposes, we'll return a mock user ID
        if email.endswith("@localhost"):
            return f"@{email.split('@')[0]}:localhost"
        return None

    def get_auth_methods(self) -> List[str]:
        """
        Get available authentication methods
        """
        return ["password", "jwt", "oidc"]


def create_module(config: Dict[str, Any], api: ModuleApi):
    return AuthManagerModule(config, api)
