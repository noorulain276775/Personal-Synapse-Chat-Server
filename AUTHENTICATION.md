# Authentication System Documentation

This document provides comprehensive documentation for the Matrix Synapse server authentication system.

## Table of Contents

1. [Overview](#overview)
2. [Authentication Methods](#authentication-methods)
3. [Password Policies](#password-policies)
4. [User Management](#user-management)
5. [API Endpoints](#api-endpoints)
6. [Frontend Integration](#frontend-integration)
7. [Security Features](#security-features)
8. [Configuration](#configuration)
9. [Testing](#testing)
10. [Troubleshooting](#troubleshooting)

## Overview

The authentication system provides multiple authentication methods, user management, and security features for the Matrix Synapse server. It includes:

- **Local Authentication**: Username/password with strong password policies
- **OIDC/SSO**: Integration with Google, GitHub, and Microsoft
- **JWT Tokens**: Secure token-based authentication
- **User Management**: Registration, profile management, and admin controls
- **Session Management**: Secure session handling with timeouts
- **Security Features**: Rate limiting, account lockout, and password validation

## Authentication Methods

### 1. Local Authentication

Local authentication uses username and password with bcrypt hashing.

**Features:**
- Strong password policies
- Account lockout after failed attempts
- Session management
- Password history tracking

**Configuration:**
```yaml
password_config:
  enabled: true
  localdb_enabled: true
  policy:
    minimum_length: 8
    require_digit: true
    require_lowercase: true
    require_uppercase: true
    require_symbol: true
    require_non_common: true
    min_entropy: 0.5
```

### 2. OIDC/SSO Authentication

OpenID Connect integration with external providers.

**Supported Providers:**
- Google
- GitHub
- Microsoft
- Custom OIDC providers

**Configuration:**
```yaml
oidc_providers:
  - idp_id: "google"
    idp_name: "Google"
    client_id: "your-google-client-id"
    client_secret: "your-google-client-secret"
    authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth"
    token_endpoint: "https://oauth2.googleapis.com/token"
    userinfo_endpoint: "https://www.googleapis.com/oauth2/v1/userinfo"
    scopes: ["openid", "profile", "email"]
```

### 3. JWT Authentication

JSON Web Token-based authentication for API access.

**Features:**
- Secure token generation
- Token validation
- Configurable expiration
- Role-based access control

**Configuration:**
```yaml
jwt_config:
  enabled: true
  secret: "your-jwt-secret-key"
  algorithm: "HS256"
  issuer: "localhost"
  audience: "matrix-synapse"
```

## Password Policies

### Password Requirements

- **Minimum Length**: 8 characters (configurable)
- **Character Types**: Must include uppercase, lowercase, numbers, and symbols
- **Common Passwords**: Rejected common passwords
- **Entropy**: Minimum entropy score for complexity
- **History**: Cannot reuse last 5 passwords

### Password Validation

```python
def validate_password_strength(password: str) -> Dict[str, Any]:
    errors = []
    
    # Check minimum length
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    
    # Check character types
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain lowercase letters")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain uppercase letters")
    
    if not re.search(r'\d', password):
        errors.append("Password must contain numbers")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain special characters")
    
    return {
        "valid": len(errors) == 0,
        "errors": errors
    }
```

## User Management

### User Registration

**Process:**
1. Validate username format and availability
2. Validate email format and uniqueness
3. Validate password strength
4. Create user account
5. Send verification email (optional)
6. Activate account

**Username Requirements:**
- 3-20 characters
- Letters, numbers, and underscores only
- Must start with a letter
- Cannot be reserved words

**Email Requirements:**
- Valid email format
- Must be unique
- Used for password reset

### User Roles

**Admin:**
- Manage users
- Manage rooms
- Manage server
- Moderate content

**Moderator:**
- Moderate content
- Manage rooms

**User:**
- Send messages
- Create rooms

### User Profile Management

**Editable Fields:**
- Display name
- Email address
- Additional metadata

**Security:**
- Email verification required for changes
- Password required for sensitive changes
- Audit logging

## API Endpoints

### Authentication Endpoints

#### POST /api/auth/login
Login with username and password.

**Request:**
```json
{
  "username": "testuser",
  "password": "password123"
}
```

**Response:**
```json
{
  "success": true,
  "user_id": "@testuser:localhost",
  "access_token": "jwt_token_here",
  "session_id": "session_id_here",
  "user": {
    "user_id": "@testuser:localhost",
    "username": "testuser",
    "email": "test@example.com",
    "display_name": "Test User",
    "role": "user"
  }
}
```

#### POST /api/auth/register
Register a new user account.

**Request:**
```json
{
  "username": "newuser",
  "email": "newuser@example.com",
  "display_name": "New User",
  "password": "SecurePassword123!"
}
```

**Response:**
```json
{
  "success": true,
  "user_id": "@newuser:localhost",
  "message": "Registration successful"
}
```

#### POST /api/auth/logout
Logout and invalidate session.

**Headers:**
```
Authorization: Bearer jwt_token_here
X-Session-ID: session_id_here
```

**Response:**
```json
{
  "success": true
}
```

#### POST /api/auth/forgot-password
Request password reset.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Password reset email sent",
  "reset_token": "reset_token_here"
}
```

#### POST /api/auth/reset-password
Reset password with token.

**Request:**
```json
{
  "reset_token": "reset_token_here",
  "new_password": "NewSecurePassword123!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Password reset successful"
}
```

### User Management Endpoints

#### GET /api/user/profile
Get current user profile.

**Headers:**
```
Authorization: Bearer jwt_token_here
```

**Response:**
```json
{
  "user_id": "@testuser:localhost",
  "username": "testuser",
  "email": "test@example.com",
  "display_name": "Test User",
  "created_at": "2024-01-01T00:00:00Z",
  "last_login": "2024-01-01T12:00:00Z",
  "role": "user"
}
```

#### PUT /api/user/profile
Update user profile.

**Headers:**
```
Authorization: Bearer jwt_token_here
```

**Request:**
```json
{
  "display_name": "Updated Name",
  "email": "newemail@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Profile updated successfully"
}
```

#### POST /api/user/change-password
Change user password.

**Headers:**
```
Authorization: Bearer jwt_token_here
```

**Request:**
```json
{
  "old_password": "oldpassword123",
  "new_password": "newpassword123!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Password changed successfully"
}
```

### Admin Endpoints

#### GET /api/admin/users
Get list of all users (admin only).

**Headers:**
```
Authorization: Bearer admin_jwt_token_here
```

**Query Parameters:**
- `page`: Page number (default: 1)
- `limit`: Users per page (default: 20)

**Response:**
```json
{
  "users": [
    {
      "user_id": "@user1:localhost",
      "username": "user1",
      "email": "user1@example.com",
      "display_name": "User One",
      "created_at": "2024-01-01T00:00:00Z",
      "last_login": "2024-01-01T12:00:00Z",
      "is_active": true,
      "role": "user"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 100,
    "pages": 5
  }
}
```

#### POST /api/admin/users/{user_id}/deactivate
Deactivate user account (admin only).

**Headers:**
```
Authorization: Bearer admin_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "message": "User deactivated successfully"
}
```

#### POST /api/admin/users/{user_id}/activate
Activate user account (admin only).

**Headers:**
```
Authorization: Bearer admin_jwt_token_here
```

**Response:**
```json
{
  "success": true,
  "message": "User activated successfully"
}
```

## Frontend Integration

### Authentication Page

The authentication system includes a comprehensive frontend at `frontend/auth.html` with:

- **Login Form**: Username/password authentication
- **Registration Form**: New user signup with validation
- **SSO Integration**: OAuth provider buttons
- **Password Reset**: Forgot password functionality
- **Real-time Validation**: Client-side form validation

### Features

- **Tabbed Interface**: Switch between login, register, and SSO
- **Password Strength Meter**: Visual password strength indicator
- **Form Validation**: Real-time input validation
- **Error Handling**: User-friendly error messages
- **Responsive Design**: Mobile-friendly interface

### Usage

1. Open `frontend/auth.html` in your browser
2. Choose authentication method
3. Fill in required information
4. Submit form to authenticate
5. Redirect to main chat interface

## Security Features

### Rate Limiting

- **Login Attempts**: Maximum 5 failed attempts
- **Lockout Duration**: 15 minutes after max attempts
- **API Requests**: 100 requests per minute per user
- **Password Reset**: 3 attempts per hour per email

### Session Management

- **Session Timeout**: 30 minutes of inactivity
- **Session Storage**: Secure server-side storage
- **Token Expiration**: 24 hours for JWT tokens
- **Concurrent Sessions**: Limited per user

### Password Security

- **Hashing**: bcrypt with salt rounds
- **History Tracking**: Prevents password reuse
- **Strength Validation**: Multiple criteria checking
- **Reset Tokens**: Time-limited and single-use

### Account Security

- **Email Verification**: Required for registration
- **Account Lockout**: After failed login attempts
- **Admin Controls**: User activation/deactivation
- **Audit Logging**: All actions logged

## Configuration

### Synapse Configuration

Add to `homeserver.yaml`:

```yaml
# Authentication modules
modules:
  - module: modules.auth_manager
    config:
      password_policy:
        minimum_length: 8
        require_digit: true
        require_lowercase: true
        require_uppercase: true
        require_symbol: true
        require_non_common: true
        min_entropy: 0.5
      jwt_secret: "your-jwt-secret-key"
      session_timeout: 1800
      max_login_attempts: 5
      lockout_duration: 900
      
  - module: modules.oidc_auth
    config:
      redirect_uri: "http://localhost:8008/_matrix/client/r0/login/sso/redirect"
      providers:
        google:
          name: "Google"
          client_id: "your-google-client-id"
          client_secret: "your-google-client-secret"
          # ... other provider config
          
  - module: modules.user_manager
    config:
      registration_enabled: true
      require_email_verification: true
      auto_approve_users: false
      max_users: 1000
      user_quota: 100
```

### API Server Configuration

Start the authentication API server:

```bash
python auth_api.py
```

The API server runs on port 8080 by default.

## Testing

### Test Script

Run the comprehensive test suite:

```bash
python test_auth.py
```

### Test Coverage

- **Health Check**: API availability
- **User Registration**: Account creation
- **User Login**: Authentication flow
- **Profile Management**: CRUD operations
- **Password Management**: Change and reset
- **Admin Functions**: User management
- **Validation**: Input validation
- **Security**: Rate limiting and lockout

### Manual Testing

1. **Start Services**:
   ```bash
   docker-compose up -d
   python auth_api.py
   ```

2. **Test Registration**:
   - Open `frontend/auth.html`
   - Try registering with weak password
   - Try registering with valid credentials

3. **Test Login**:
   - Login with valid credentials
   - Try multiple failed attempts
   - Verify account lockout

4. **Test Admin Functions**:
   - Login as admin
   - View user list
   - Deactivate/activate users

## Troubleshooting

### Common Issues

#### 1. Authentication API Not Starting

**Error**: `ModuleNotFoundError: No module named 'aiohttp'`

**Solution**:
```bash
pip install -r requirements.txt
```

#### 2. JWT Token Invalid

**Error**: `Invalid token` in API responses

**Solution**:
- Check JWT secret configuration
- Verify token expiration
- Ensure proper Authorization header format

#### 3. User Registration Fails

**Error**: `Invalid username` or `Invalid password`

**Solution**:
- Check username format requirements
- Verify password strength criteria
- Ensure email format is valid

#### 4. SSO Not Working

**Error**: OAuth provider errors

**Solution**:
- Verify client ID and secret
- Check redirect URI configuration
- Ensure provider endpoints are accessible

#### 5. Database Connection Issues

**Error**: `Database connection failed`

**Solution**:
- Check PostgreSQL container status
- Verify database credentials
- Ensure proper network connectivity

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Logs

Check service logs:

```bash
# Synapse logs
docker-compose logs -f synapse

# API logs
tail -f auth_api.log

# Database logs
docker-compose logs -f postgres
```

### Performance Issues

- **Slow Authentication**: Check Redis connection
- **High Memory Usage**: Monitor session storage
- **Database Bottlenecks**: Check connection pooling
- **Rate Limiting**: Adjust limits if needed

## Security Best Practices

### Production Deployment

1. **Change Default Secrets**: Update all default passwords and secrets
2. **Enable HTTPS**: Use SSL/TLS for all communications
3. **Database Security**: Use strong database passwords
4. **Network Security**: Configure proper firewall rules
5. **Regular Updates**: Keep all dependencies updated

### Monitoring

1. **Failed Login Attempts**: Monitor for brute force attacks
2. **Unusual Activity**: Track suspicious user behavior
3. **System Resources**: Monitor CPU, memory, and disk usage
4. **Error Rates**: Track authentication failure rates

### Backup and Recovery

1. **Database Backups**: Regular PostgreSQL backups
2. **Configuration Backups**: Backup all configuration files
3. **User Data**: Ensure user data is properly backed up
4. **Disaster Recovery**: Test recovery procedures
