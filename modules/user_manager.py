"""
User Management Module for Synapse
Handles user registration, profile management, and administrative functions
"""

import logging
import time
import secrets
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import bcrypt
import re

from synapse.module_api import ModuleApi

logger = logging.getLogger(__name__)


class UserManagerModule:
    def __init__(self, config: Dict[str, Any], api: ModuleApi):
        self.api = api
        self.config = config
        
        # User management settings
        self.registration_enabled = config.get("registration_enabled", True)
        self.require_email_verification = config.get("require_email_verification", True)
        self.auto_approve_users = config.get("auto_approve_users", False)
        self.max_users = config.get("max_users", 1000)
        self.user_quota = config.get("user_quota", 100)  # MB per user
        
        # User roles and permissions
        self.user_roles = {
            "admin": ["manage_users", "manage_rooms", "manage_server", "moderate"],
            "moderator": ["moderate", "manage_rooms"],
            "user": ["send_messages", "create_rooms"]
        }
        
        # In-memory storage for demo (use database in production)
        self.user_profiles = {}
        self.user_roles_storage = {}
        self.pending_registrations = {}
        self.user_activity = {}
        
        logger.info("UserManagerModule initialized")

    def validate_username(self, username: str) -> Dict[str, Any]:
        """
        Validate username format and availability
        """
        errors = []
        
        # Check length
        if len(username) < 3:
            errors.append("Username must be at least 3 characters long")
        elif len(username) > 20:
            errors.append("Username must be no more than 20 characters long")
        
        # Check format (alphanumeric and underscores only)
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            errors.append("Username can only contain letters, numbers, and underscores")
        
        # Check if starts with letter
        if not re.match(r'^[a-zA-Z]', username):
            errors.append("Username must start with a letter")
        
        # Check for reserved words
        reserved_words = ["admin", "root", "system", "matrix", "synapse", "server"]
        if username.lower() in reserved_words:
            errors.append("Username is reserved")
        
        # Check availability
        user_id = f"@{username}:localhost"
        if user_id in self.user_profiles:
            errors.append("Username already taken")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }

    def validate_email(self, email: str) -> bool:
        """
        Validate email format
        """
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def generate_verification_code(self) -> str:
        """
        Generate a verification code for email verification
        """
        return secrets.token_urlsafe(16)

    def hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt
        """
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode(), salt).decode()

    async def register_user(self, username: str, password: str, email: str, 
                          display_name: str = "", additional_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Register a new user
        """
        try:
            # Validate input
            username_validation = self.validate_username(username)
            if not username_validation["valid"]:
                return {
                    "success": False,
                    "errors": username_validation["errors"]
                }
            
            if not self.validate_email(email):
                return {
                    "success": False,
                    "errors": ["Invalid email format"]
                }
            
            # Check if registration is enabled
            if not self.registration_enabled:
                return {
                    "success": False,
                    "errors": ["Registration is currently disabled"]
                }
            
            # Check user limit
            if len(self.user_profiles) >= self.max_users:
                return {
                    "success": False,
                    "errors": ["Maximum number of users reached"]
                }
            
            # Check if email is already used
            for profile in self.user_profiles.values():
                if profile.get("email") == email:
                    return {
                        "success": False,
                        "errors": ["Email already registered"]
                    }
            
            user_id = f"@{username}:localhost"
            
            # Create user profile
            user_profile = {
                "user_id": user_id,
                "username": username,
                "email": email,
                "display_name": display_name or username,
                "password_hash": self.hash_password(password),
                "created_at": time.time(),
                "last_login": None,
                "is_active": True,
                "is_verified": not self.require_email_verification,
                "role": "user",
                "quota_used": 0,
                "additional_data": additional_data or {}
            }
            
            # Store user profile
            self.user_profiles[user_id] = user_profile
            self.user_roles_storage[user_id] = ["user"]
            
            # Generate verification code if needed
            if self.require_email_verification:
                verification_code = self.generate_verification_code()
                self.pending_registrations[verification_code] = {
                    "user_id": user_id,
                    "email": email,
                    "created_at": time.time()
                }
                
                # In production, send verification email
                logger.info(f"Verification code for {email}: {verification_code}")
                
                return {
                    "success": True,
                    "user_id": user_id,
                    "verification_required": True,
                    "verification_code": verification_code  # Only for demo
                }
            else:
                return {
                    "success": True,
                    "user_id": user_id,
                    "verification_required": False
                }
                
        except Exception as e:
            logger.error(f"Error registering user: {e}")
            return {
                "success": False,
                "errors": ["Registration failed"]
            }

    async def verify_email(self, verification_code: str) -> Dict[str, Any]:
        """
        Verify user email with verification code
        """
        try:
            if verification_code not in self.pending_registrations:
                return {
                    "success": False,
                    "errors": ["Invalid verification code"]
                }
            
            registration_data = self.pending_registrations[verification_code]
            
            # Check if verification code has expired (24 hours)
            if time.time() - registration_data["created_at"] > 86400:
                del self.pending_registrations[verification_code]
                return {
                    "success": False,
                    "errors": ["Verification code has expired"]
                }
            
            user_id = registration_data["user_id"]
            
            # Mark user as verified
            if user_id in self.user_profiles:
                self.user_profiles[user_id]["is_verified"] = True
            
            # Remove from pending registrations
            del self.pending_registrations[verification_code]
            
            return {
                "success": True,
                "user_id": user_id
            }
            
        except Exception as e:
            logger.error(f"Error verifying email: {e}")
            return {
                "success": False,
                "errors": ["Verification failed"]
            }

    async def get_user_profile(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user profile information
        """
        if user_id not in self.user_profiles:
            return None
        
        profile = self.user_profiles[user_id].copy()
        
        # Remove sensitive information
        profile.pop("password_hash", None)
        
        return profile

    async def update_user_profile(self, user_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update user profile information
        """
        try:
            if user_id not in self.user_profiles:
                return {
                    "success": False,
                    "errors": ["User not found"]
                }
            
            # Validate updates
            if "email" in updates and not self.validate_email(updates["email"]):
                return {
                    "success": False,
                    "errors": ["Invalid email format"]
                }
            
            if "display_name" in updates and len(updates["display_name"]) > 50:
                return {
                    "success": False,
                    "errors": ["Display name too long"]
                }
            
            # Update profile
            for key, value in updates.items():
                if key in ["display_name", "email", "additional_data"]:
                    self.user_profiles[user_id][key] = value
            
            return {
                "success": True,
                "profile": await self.get_user_profile(user_id)
            }
            
        except Exception as e:
            logger.error(f"Error updating user profile: {e}")
            return {
                "success": False,
                "errors": ["Update failed"]
            }

    async def change_password(self, user_id: str, old_password: str, new_password: str) -> Dict[str, Any]:
        """
        Change user password
        """
        try:
            if user_id not in self.user_profiles:
                return {
                    "success": False,
                    "errors": ["User not found"]
                }
            
            # Verify old password
            stored_hash = self.user_profiles[user_id]["password_hash"]
            if not bcrypt.checkpw(old_password.encode(), stored_hash.encode()):
                return {
                    "success": False,
                    "errors": ["Current password is incorrect"]
                }
            
            # Validate new password
            if len(new_password) < 8:
                return {
                    "success": False,
                    "errors": ["New password must be at least 8 characters long"]
                }
            
            # Update password
            self.user_profiles[user_id]["password_hash"] = self.hash_password(new_password)
            
            return {
                "success": True
            }
            
        except Exception as e:
            logger.error(f"Error changing password: {e}")
            return {
                "success": False,
                "errors": ["Password change failed"]
            }

    async def assign_user_role(self, user_id: str, role: str, admin_user_id: str) -> Dict[str, Any]:
        """
        Assign a role to a user (admin only)
        """
        try:
            # Check if admin user has permission
            if not await self.has_permission(admin_user_id, "manage_users"):
                return {
                    "success": False,
                    "errors": ["Insufficient permissions"]
                }
            
            if role not in self.user_roles:
                return {
                    "success": False,
                    "errors": ["Invalid role"]
                }
            
            if user_id not in self.user_profiles:
                return {
                    "success": False,
                    "errors": ["User not found"]
                }
            
            # Assign role
            if user_id not in self.user_roles_storage:
                self.user_roles_storage[user_id] = []
            
            if role not in self.user_roles_storage[user_id]:
                self.user_roles_storage[user_id].append(role)
            
            return {
                "success": True,
                "roles": self.user_roles_storage[user_id]
            }
            
        except Exception as e:
            logger.error(f"Error assigning role: {e}")
            return {
                "success": False,
                "errors": ["Role assignment failed"]
            }

    async def has_permission(self, user_id: str, permission: str) -> bool:
        """
        Check if user has a specific permission
        """
        if user_id not in self.user_roles_storage:
            return False
        
        user_roles = self.user_roles_storage[user_id]
        
        for role in user_roles:
            if permission in self.user_roles.get(role, []):
                return True
        
        return False

    async def get_user_list(self, admin_user_id: str, page: int = 1, limit: int = 20) -> Dict[str, Any]:
        """
        Get list of users (admin only)
        """
        try:
            if not await self.has_permission(admin_user_id, "manage_users"):
                return {
                    "success": False,
                    "errors": ["Insufficient permissions"]
                }
            
            # Get paginated user list
            start = (page - 1) * limit
            end = start + limit
            
            user_list = []
            for user_id, profile in list(self.user_profiles.items())[start:end]:
                user_info = {
                    "user_id": user_id,
                    "username": profile["username"],
                    "email": profile["email"],
                    "display_name": profile["display_name"],
                    "created_at": profile["created_at"],
                    "last_login": profile["last_login"],
                    "is_active": profile["is_active"],
                    "is_verified": profile["is_verified"],
                    "roles": self.user_roles_storage.get(user_id, [])
                }
                user_list.append(user_info)
            
            total_users = len(self.user_profiles)
            
            return {
                "success": True,
                "users": user_list,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total_users,
                    "pages": (total_users + limit - 1) // limit
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting user list: {e}")
            return {
                "success": False,
                "errors": ["Failed to get user list"]
            }

    async def deactivate_user(self, user_id: str, admin_user_id: str) -> Dict[str, Any]:
        """
        Deactivate a user account (admin only)
        """
        try:
            if not await self.has_permission(admin_user_id, "manage_users"):
                return {
                    "success": False,
                    "errors": ["Insufficient permissions"]
                }
            
            if user_id not in self.user_profiles:
                return {
                    "success": False,
                    "errors": ["User not found"]
                }
            
            # Deactivate user
            self.user_profiles[user_id]["is_active"] = False
            
            return {
                "success": True
            }
            
        except Exception as e:
            logger.error(f"Error deactivating user: {e}")
            return {
                "success": False,
                "errors": ["Deactivation failed"]
            }


def create_module(config: Dict[str, Any], api: ModuleApi):
    return UserManagerModule(config, api)
