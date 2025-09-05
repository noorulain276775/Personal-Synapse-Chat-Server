#!/usr/bin/env python3
"""
Authentication API for Matrix Synapse Server
Provides REST API endpoints for user authentication and management
"""

import asyncio
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import jwt
import bcrypt
import secrets
import re

from aiohttp import web, ClientSession
from aiohttp_cors import setup as cors_setup, ResourceOptions

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AuthAPI:
    def __init__(self):
        self.app = web.Application()
        self.setup_cors()
        self.setup_routes()
        
        # Configuration
        self.jwt_secret = "your-jwt-secret-key-change-this-in-production"
        self.session_timeout = 1800  # 30 minutes
        self.max_login_attempts = 5
        self.lockout_duration = 900  # 15 minutes
        
        # In-memory storage (use database in production)
        self.users = {}
        self.sessions = {}
        self.failed_attempts = {}
        self.password_reset_tokens = {}
        
        # Initialize with demo admin user
        self.create_demo_user()
    
    def setup_cors(self):
        """Setup CORS for cross-origin requests"""
        cors = cors_setup(self.app, defaults={
            "*": ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods="*"
            )
        })
        
        # Add CORS to all routes
        for route in list(self.app.router.routes()):
            cors.add(route)
    
    def setup_routes(self):
        """Setup API routes"""
        # Authentication routes
        self.app.router.add_post('/api/auth/login', self.handle_login)
        self.app.router.add_post('/api/auth/register', self.handle_register)
        self.app.router.add_post('/api/auth/logout', self.handle_logout)
        self.app.router.add_post('/api/auth/refresh', self.handle_refresh)
        self.app.router.add_post('/api/auth/forgot-password', self.handle_forgot_password)
        self.app.router.add_post('/api/auth/reset-password', self.handle_reset_password)
        
        # User management routes
        self.app.router.add_get('/api/user/profile', self.handle_get_profile)
        self.app.router.add_put('/api/user/profile', self.handle_update_profile)
        self.app.router.add_post('/api/user/change-password', self.handle_change_password)
        
        # Admin routes
        self.app.router.add_get('/api/admin/users', self.handle_get_users)
        self.app.router.add_post('/api/admin/users/{user_id}/deactivate', self.handle_deactivate_user)
        self.app.router.add_post('/api/admin/users/{user_id}/activate', self.handle_activate_user)
        
        # Health check
        self.app.router.add_get('/api/health', self.handle_health)
    
    def create_demo_user(self):
        """Create a demo admin user"""
        admin_password = "admin123"
        password_hash = bcrypt.hashpw(admin_password.encode(), bcrypt.gensalt()).decode()
        
        self.users["@admin:localhost"] = {
            "user_id": "@admin:localhost",
            "username": "admin",
            "email": "admin@localhost",
            "display_name": "Administrator",
            "password_hash": password_hash,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": None,
            "is_active": True,
            "is_verified": True,
            "role": "admin"
        }
    
    def validate_password(self, password: str) -> Dict[str, Any]:
        """Validate password strength"""
        errors = []
        
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }
    
    def validate_username(self, username: str) -> Dict[str, Any]:
        """Validate username format"""
        errors = []
        
        if len(username) < 3:
            errors.append("Username must be at least 3 characters long")
        elif len(username) > 20:
            errors.append("Username must be no more than 20 characters long")
        
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            errors.append("Username can only contain letters, numbers, and underscores")
        
        if not re.match(r'^[a-zA-Z]', username):
            errors.append("Username must start with a letter")
        
        # Check if username is already taken
        user_id = f"@{username}:localhost"
        if user_id in self.users:
            errors.append("Username already taken")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }
    
    def validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def generate_jwt_token(self, user_id: str) -> str:
        """Generate JWT token for user"""
        payload = {
            "user_id": user_id,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=24),
            "iss": "matrix-synapse",
            "aud": "matrix-client"
        }
        
        return jwt.encode(payload, self.jwt_secret, algorithm="HS256")
    
    def validate_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def is_user_locked_out(self, user_id: str) -> bool:
        """Check if user is locked out due to failed attempts"""
        if user_id not in self.failed_attempts:
            return False
        
        attempts = self.failed_attempts[user_id]
        if attempts["count"] >= self.max_login_attempts:
            lockout_time = attempts["last_attempt"] + self.lockout_duration
            if datetime.utcnow().timestamp() < lockout_time:
                return True
            else:
                del self.failed_attempts[user_id]
        
        return False
    
    def record_failed_attempt(self, user_id: str):
        """Record a failed login attempt"""
        if user_id not in self.failed_attempts:
            self.failed_attempts[user_id] = {"count": 0, "last_attempt": 0}
        
        self.failed_attempts[user_id]["count"] += 1
        self.failed_attempts[user_id]["last_attempt"] = datetime.utcnow().timestamp()
    
    def clear_failed_attempts(self, user_id: str):
        """Clear failed attempts for successful login"""
        if user_id in self.failed_attempts:
            del self.failed_attempts[user_id]
    
    async def handle_login(self, request):
        """Handle user login"""
        try:
            data = await request.json()
            username = data.get("username", "")
            password = data.get("password", "")
            
            if not username or not password:
                return web.json_response(
                    {"error": "Username and password are required"},
                    status=400
                )
            
            user_id = f"@{username}:localhost"
            
            # Check if user exists
            if user_id not in self.users:
                return web.json_response(
                    {"error": "Invalid username or password"},
                    status=401
                )
            
            user = self.users[user_id]
            
            # Check if user is locked out
            if self.is_user_locked_out(user_id):
                return web.json_response(
                    {"error": "Account is temporarily locked due to too many failed attempts"},
                    status=423
                )
            
            # Check if user is active
            if not user["is_active"]:
                return web.json_response(
                    {"error": "Account is deactivated"},
                    status=403
                )
            
            # Verify password
            if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
                self.record_failed_attempt(user_id)
                return web.json_response(
                    {"error": "Invalid username or password"},
                    status=401
                )
            
            # Clear failed attempts
            self.clear_failed_attempts(user_id)
            
            # Update last login
            user["last_login"] = datetime.utcnow().isoformat()
            
            # Generate JWT token
            token = self.generate_jwt_token(user_id)
            
            # Create session
            session_id = secrets.token_urlsafe(32)
            self.sessions[session_id] = {
                "user_id": user_id,
                "created_at": datetime.utcnow().timestamp(),
                "last_activity": datetime.utcnow().timestamp()
            }
            
            return web.json_response({
                "success": True,
                "user_id": user_id,
                "access_token": token,
                "session_id": session_id,
                "user": {
                    "user_id": user_id,
                    "username": user["username"],
                    "email": user["email"],
                    "display_name": user["display_name"],
                    "role": user["role"]
                }
            })
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return web.json_response(
                {"error": "Internal server error"},
                status=500
            )
    
    async def handle_register(self, request):
        """Handle user registration"""
        try:
            data = await request.json()
            username = data.get("username", "")
            email = data.get("email", "")
            display_name = data.get("display_name", "")
            password = data.get("password", "")
            
            # Validate input
            username_validation = self.validate_username(username)
            if not username_validation["valid"]:
                return web.json_response(
                    {"error": "Invalid username", "details": username_validation["errors"]},
                    status=400
                )
            
            if not self.validate_email(email):
                return web.json_response(
                    {"error": "Invalid email format"},
                    status=400
                )
            
            password_validation = self.validate_password(password)
            if not password_validation["valid"]:
                return web.json_response(
                    {"error": "Invalid password", "details": password_validation["errors"]},
                    status=400
                )
            
            # Check if email is already used
            for user in self.users.values():
                if user["email"] == email:
                    return web.json_response(
                        {"error": "Email already registered"},
                        status=400
                    )
            
            # Create user
            user_id = f"@{username}:localhost"
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            
            self.users[user_id] = {
                "user_id": user_id,
                "username": username,
                "email": email,
                "display_name": display_name or username,
                "password_hash": password_hash,
                "created_at": datetime.utcnow().isoformat(),
                "last_login": None,
                "is_active": True,
                "is_verified": True,  # Auto-verify for demo
                "role": "user"
            }
            
            return web.json_response({
                "success": True,
                "user_id": user_id,
                "message": "Registration successful"
            })
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return web.json_response(
                {"error": "Internal server error"},
                status=500
            )
    
    async def handle_logout(self, request):
        """Handle user logout"""
        try:
            # Get session ID from headers
            session_id = request.headers.get("X-Session-ID")
            
            if session_id and session_id in self.sessions:
                del self.sessions[session_id]
            
            return web.json_response({"success": True})
            
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return web.json_response(
                {"error": "Internal server error"},
                status=500
            )
    
    async def handle_refresh(self, request):
        """Handle token refresh"""
        try:
            data = await request.json()
            refresh_token = data.get("refresh_token", "")
            
            # In a real implementation, you would validate the refresh token
            # For demo purposes, we'll just return a new token
            
            return web.json_response({
                "success": True,
                "access_token": "new_access_token_here"
            })
            
        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            return web.json_response(
                {"error": "Internal server error"},
                status=500
            )
    
    async def handle_forgot_password(self, request):
        """Handle forgot password request"""
        try:
            data = await request.json()
            email = data.get("email", "")
            
            if not email:
                return web.json_response(
                    {"error": "Email is required"},
                    status=400
                )
            
            # Find user by email
            user = None
            for u in self.users.values():
                if u["email"] == email:
                    user = u
                    break
            
            if not user:
                return web.json_response(
                    {"error": "Email not found"},
                    status=404
                )
            
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            self.password_reset_tokens[reset_token] = {
                "user_id": user["user_id"],
                "created_at": datetime.utcnow().timestamp(),
                "used": False
            }
            
            # In production, send email with reset link
            logger.info(f"Password reset token for {email}: {reset_token}")
            
            return web.json_response({
                "success": True,
                "message": "Password reset email sent",
                "reset_token": reset_token  # Only for demo
            })
            
        except Exception as e:
            logger.error(f"Forgot password error: {e}")
            return web.json_response(
                {"error": "Internal server error"},
                status=500
            )
    
    async def handle_reset_password(self, request):
        """Handle password reset"""
        try:
            data = await request.json()
            reset_token = data.get("reset_token", "")
            new_password = data.get("new_password", "")
            
            if not reset_token or not new_password:
                return web.json_response(
                    {"error": "Reset token and new password are required"},
                    status=400
                )
            
            # Validate reset token
            if reset_token not in self.password_reset_tokens:
                return web.json_response(
                    {"error": "Invalid reset token"},
                    status=400
                )
            
            token_data = self.password_reset_tokens[reset_token]
            
            # Check if token has expired (1 hour)
            if datetime.utcnow().timestamp() - token_data["created_at"] > 3600:
                del self.password_reset_tokens[reset_token]
                return web.json_response(
                    {"error": "Reset token has expired"},
                    status=400
                )
            
            # Check if token has been used
            if token_data["used"]:
                return web.json_response(
                    {"error": "Reset token has already been used"},
                    status=400
                )
            
            # Validate new password
            password_validation = self.validate_password(new_password)
            if not password_validation["valid"]:
                return web.json_response(
                    {"error": "Invalid password", "details": password_validation["errors"]},
                    status=400
                )
            
            # Update password
            user_id = token_data["user_id"]
            if user_id in self.users:
                self.users[user_id]["password_hash"] = bcrypt.hashpw(
                    new_password.encode(), 
                    bcrypt.gensalt()
                ).decode()
            
            # Mark token as used
            token_data["used"] = True
            
            return web.json_response({
                "success": True,
                "message": "Password reset successful"
            })
            
        except Exception as e:
            logger.error(f"Password reset error: {e}")
            return web.json_response(
                {"error": "Internal server error"},
                status=500
            )
    
    async def handle_get_profile(self, request):
        """Get user profile"""
        try:
            # Get user ID from JWT token
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return web.json_response(
                    {"error": "Authorization header required"},
                    status=401
                )
            
            token = auth_header[7:]
            payload = self.validate_jwt_token(token)
            if not payload:
                return web.json_response(
                    {"error": "Invalid token"},
                    status=401
                )
            
            user_id = payload["user_id"]
            if user_id not in self.users:
                return web.json_response(
                    {"error": "User not found"},
                    status=404
                )
            
            user = self.users[user_id]
            profile = {
                "user_id": user["user_id"],
                "username": user["username"],
                "email": user["email"],
                "display_name": user["display_name"],
                "created_at": user["created_at"],
                "last_login": user["last_login"],
                "role": user["role"]
            }
            
            return web.json_response(profile)
            
        except Exception as e:
            logger.error(f"Get profile error: {e}")
            return web.json_response(
                {"error": "Internal server error"},
                status=500
            )
    
    async def handle_update_profile(self, request):
        """Update user profile"""
        try:
            # Get user ID from JWT token
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return web.json_response(
                    {"error": "Authorization header required"},
                    status=401
                )
            
            token = auth_header[7:]
            payload = self.validate_jwt_token(token)
            if not payload:
                return web.json_response(
                    {"error": "Invalid token"},
                    status=401
                )
            
            user_id = payload["user_id"]
            if user_id not in self.users:
                return web.json_response(
                    {"error": "User not found"},
                    status=404
                )
            
            data = await request.json()
            
            # Update allowed fields
            if "display_name" in data:
                self.users[user_id]["display_name"] = data["display_name"]
            
            if "email" in data:
                if not self.validate_email(data["email"]):
                    return web.json_response(
                        {"error": "Invalid email format"},
                        status=400
                    )
                self.users[user_id]["email"] = data["email"]
            
            return web.json_response({
                "success": True,
                "message": "Profile updated successfully"
            })
            
        except Exception as e:
            logger.error(f"Update profile error: {e}")
            return web.json_response(
                {"error": "Internal server error"},
                status=500
            )
    
    async def handle_change_password(self, request):
        """Change user password"""
        try:
            # Get user ID from JWT token
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return web.json_response(
                    {"error": "Authorization header required"},
                    status=401
                )
            
            token = auth_header[7:]
            payload = self.validate_jwt_token(token)
            if not payload:
                return web.json_response(
                    {"error": "Invalid token"},
                    status=401
                )
            
            user_id = payload["user_id"]
            if user_id not in self.users:
                return web.json_response(
                    {"error": "User not found"},
                    status=404
                )
            
            data = await request.json()
            old_password = data.get("old_password", "")
            new_password = data.get("new_password", "")
            
            # Verify old password
            user = self.users[user_id]
            if not bcrypt.checkpw(old_password.encode(), user["password_hash"].encode()):
                return web.json_response(
                    {"error": "Current password is incorrect"},
                    status=400
                )
            
            # Validate new password
            password_validation = self.validate_password(new_password)
            if not password_validation["valid"]:
                return web.json_response(
                    {"error": "Invalid password", "details": password_validation["errors"]},
                    status=400
                )
            
            # Update password
            self.users[user_id]["password_hash"] = bcrypt.hashpw(
                new_password.encode(), 
                bcrypt.gensalt()
            ).decode()
            
            return web.json_response({
                "success": True,
                "message": "Password changed successfully"
            })
            
        except Exception as e:
            logger.error(f"Change password error: {e}")
            return web.json_response(
                {"error": "Internal server error"},
                status=500
            )
    
    async def handle_get_users(self, request):
        """Get list of users (admin only)"""
        try:
            # Get user ID from JWT token
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return web.json_response(
                    {"error": "Authorization header required"},
                    status=401
                )
            
            token = auth_header[7:]
            payload = self.validate_jwt_token(token)
            if not payload:
                return web.json_response(
                    {"error": "Invalid token"},
                    status=401
                )
            
            user_id = payload["user_id"]
            if user_id not in self.users or self.users[user_id]["role"] != "admin":
                return web.json_response(
                    {"error": "Admin access required"},
                    status=403
                )
            
            # Get pagination parameters
            page = int(request.query.get("page", 1))
            limit = int(request.query.get("limit", 20))
            
            # Get user list
            user_list = []
            for user in self.users.values():
                user_info = {
                    "user_id": user["user_id"],
                    "username": user["username"],
                    "email": user["email"],
                    "display_name": user["display_name"],
                    "created_at": user["created_at"],
                    "last_login": user["last_login"],
                    "is_active": user["is_active"],
                    "role": user["role"]
                }
                user_list.append(user_info)
            
            # Pagination
            start = (page - 1) * limit
            end = start + limit
            paginated_users = user_list[start:end]
            
            return web.json_response({
                "users": paginated_users,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": len(user_list),
                    "pages": (len(user_list) + limit - 1) // limit
                }
            })
            
        except Exception as e:
            logger.error(f"Get users error: {e}")
            return web.json_response(
                {"error": "Internal server error"},
                status=500
            )
    
    async def handle_deactivate_user(self, request):
        """Deactivate user (admin only)"""
        try:
            # Get user ID from JWT token
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return web.json_response(
                    {"error": "Authorization header required"},
                    status=401
                )
            
            token = auth_header[7:]
            payload = self.validate_jwt_token(token)
            if not payload:
                return web.json_response(
                    {"error": "Invalid token"},
                    status=401
                )
            
            admin_user_id = payload["user_id"]
            if admin_user_id not in self.users or self.users[admin_user_id]["role"] != "admin":
                return web.json_response(
                    {"error": "Admin access required"},
                    status=403
                )
            
            # Get target user ID from URL
            target_user_id = request.match_info["user_id"]
            if target_user_id not in self.users:
                return web.json_response(
                    {"error": "User not found"},
                    status=404
                )
            
            # Deactivate user
            self.users[target_user_id]["is_active"] = False
            
            return web.json_response({
                "success": True,
                "message": "User deactivated successfully"
            })
            
        except Exception as e:
            logger.error(f"Deactivate user error: {e}")
            return web.json_response(
                {"error": "Internal server error"},
                status=500
            )
    
    async def handle_activate_user(self, request):
        """Activate user (admin only)"""
        try:
            # Get user ID from JWT token
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return web.json_response(
                    {"error": "Authorization header required"},
                    status=401
                )
            
            token = auth_header[7:]
            payload = self.validate_jwt_token(token)
            if not payload:
                return web.json_response(
                    {"error": "Invalid token"},
                    status=401
                )
            
            admin_user_id = payload["user_id"]
            if admin_user_id not in self.users or self.users[admin_user_id]["role"] != "admin":
                return web.json_response(
                    {"error": "Admin access required"},
                    status=403
                )
            
            # Get target user ID from URL
            target_user_id = request.match_info["user_id"]
            if target_user_id not in self.users:
                return web.json_response(
                    {"error": "User not found"},
                    status=404
                )
            
            # Activate user
            self.users[target_user_id]["is_active"] = True
            
            return web.json_response({
                "success": True,
                "message": "User activated successfully"
            })
            
        except Exception as e:
            logger.error(f"Activate user error: {e}")
            return web.json_response(
                {"error": "Internal server error"},
                status=500
            )
    
    async def handle_health(self, request):
        """Health check endpoint"""
        return web.json_response({
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "users_count": len(self.users),
            "sessions_count": len(self.sessions)
        })

def main():
    """Run the authentication API server"""
    auth_api = AuthAPI()
    
    print("🚀 Starting Authentication API Server...")
    print("📡 Server will be available at: http://localhost:8080")
    print("📚 API Documentation:")
    print("  POST /api/auth/login - User login")
    print("  POST /api/auth/register - User registration")
    print("  POST /api/auth/logout - User logout")
    print("  GET  /api/user/profile - Get user profile")
    print("  PUT  /api/user/profile - Update user profile")
    print("  POST /api/user/change-password - Change password")
    print("  GET  /api/admin/users - Get users list (admin)")
    print("  GET  /api/health - Health check")
    
    web.run_app(auth_api.app, host='0.0.0.0', port=8080)

if __name__ == "__main__":
    main()
