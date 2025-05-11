import os
import uuid
import logging
import json
import time
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
from flask import Blueprint, request, jsonify, session, g, redirect, url_for, current_app
import bcrypt
import jwt
import secrets
import re
from functools import wraps

# Import services
from services.database import DatabaseService
from services.monitor import MonitoringService

# Configure logging
logger = logging.getLogger("triton.auth")

# Create Blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# Get database service instance
def get_db():
    """Get database service instance"""
    if not hasattr(g, 'db_service'):
        db_path = current_app.config.get("DATABASE_PATH", "triton.db")
        g.db_service = DatabaseService(db_path, current_app.config)
    return g.db_service

# Get monitoring service instance
def get_monitor():
    """Get monitoring service instance"""
    if not hasattr(g, 'monitor_service'):
        g.monitor_service = MonitoringService(
            app_name="Triton Auth",
            config=current_app.config
        )
    return g.monitor_service

# Password validation regex patterns
PASSWORD_PATTERNS = {
    "length": r".{8,}",                         # At least 8 characters
    "uppercase": r"[A-Z]",                      # At least one uppercase letter
    "lowercase": r"[a-z]",                      # At least one lowercase letter
    "digit": r"\d",                             # At least one digit
    "special": r"[!@#$%^&*(),.?\":{}|<>]"       # At least one special character
}

# Email validation regex
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

# Authentication routes
@auth_bp.route('/login', methods=['POST'])
def login():
    """Authenticate user and create session
    
    Request body:
    {
        "email": "user@example.com",
        "password": "password123"
    }
    
    Returns:
        JWT token and session information
    """
    try:
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        
        # Validate email format
        if not re.match(EMAIL_REGEX, email):
            return jsonify({"error": "Invalid email format"}), 400
        
        # Get user by email
        db = get_db()
        user = db.get_user_by_email(email)
        
        if not user:
            logger.warning(f"Login attempt for unknown email: {email}")
            # Use same response as invalid password to prevent email enumeration
            return jsonify({"error": "Invalid email or password"}), 401
        
        # Verify password
        if not verify_password(password, user["password_hash"]):
            logger.warning(f"Failed login attempt for email: {email}")
            return jsonify({"error": "Invalid email or password"}), 401
        
        # Create session
        request_info = {
            "ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", "")
        }
        
        # Create session token
        session_token = create_session(user["user_id"], request_info)
        
        # Store in HTTP-only cookie
        session['auth_token'] = session_token
        
        # Generate JWT token for API access
        jwt_token = generate_jwt_token(user["user_id"])
        
        # Update last login timestamp
        update_last_login(user["user_id"])
        
        # Log successful login
        logger.info(f"User {user['username']} ({user['email']}) logged in successfully")
        
        # Get user data without sensitive information
        user_data = db.get_user_by_id(user["user_id"])
        
        return jsonify({
            "token": jwt_token,
            "user": user_data,
            "message": "Login successful"
        })
    
    except Exception as e:
        monitor = get_monitor()
        error_id = monitor.log_error(e)
        logger.error(f"Login error {error_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "An error occurred during login", "error_id": error_id}), 500

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user with invitation token
    
    Request body:
    {
        "username": "johndoe",
        "email": "john@example.com",
        "password": "Password123!",
        "invite_token": "invitation_token"
    }
    
    Returns:
        User information and session token
    """
    try:
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Extract and validate required fields
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        invite_token = data.get('invite_token', '').strip()
        
        # Validate required fields
        validation_errors = validate_registration_data(username, email, password)
        if validation_errors:
            return jsonify({"error": "Validation failed", "details": validation_errors}), 400
        
        db = get_db()
        
        # Check if invitation is valid
        invitation = validate_invitation(invite_token, email)
        if not invitation:
            return jsonify({"error": "Invalid or expired invitation token"}), 400
        
        # Check if email is already registered
        existing_user = db.get_user_by_email(email)
        if existing_user:
            return jsonify({"error": "Email already registered"}), 409
        
        # Create user
        user_id = str(uuid.uuid4())
        password_hash = hash_password(password)
        
        # Default to regular user role
        role = "user"
        
        # Create user object
        user_data = {
            "user_id": user_id,
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "role": role
        }
        
        # Create user in database
        db.create_user(user_data)
        
        # Mark invitation as used
        db.mark_invitation_used(invitation["invitation_id"])
        
        # Create session for the new user
        request_info = {
            "ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", "")
        }
        
        # Create session token
        session_token = create_session(user_id, request_info)
        
        # Store in HTTP-only cookie
        session['auth_token'] = session_token
        
        # Generate JWT token for API access
        jwt_token = generate_jwt_token(user_id)
        
        # Get user data without sensitive information
        user_data = db.get_user_by_id(user_id)
        
        # Log successful registration
        logger.info(f"New user registered: {username} ({email})")
        
        return jsonify({
            "token": jwt_token,
            "user": user_data,
            "message": "Registration successful"
        }), 201
    
    except Exception as e:
        monitor = get_monitor()
        error_id = monitor.log_error(e)
        logger.error(f"Registration error {error_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "An error occurred during registration", "error_id": error_id}), 500

@auth_bp.route('/validate-invitation', methods=['POST'])
def validate_invitation_token():
    """Validate an invitation token
    
    Request body:
    {
        "token": "invitation_token",
        "email": "invited@example.com"
    }
    
    Returns:
        Invitation information if valid
    """
    try:
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        token = data.get('token', '').strip()
        email = data.get('email', '').strip().lower()
        
        if not token or not email:
            return jsonify({"error": "Token and email are required"}), 400
        
        # Check if invitation is valid
        invitation = validate_invitation(token, email)
        if not invitation:
            return jsonify({"error": "Invalid or expired invitation token"}), 400
        
        # Return invitation info
        return jsonify({
            "valid": True,
            "email": email,
            "invitation_id": invitation["invitation_id"],
            "expires_at": invitation["expires_at"]
        })
    
    except Exception as e:
        monitor = get_monitor()
        error_id = monitor.log_error(e)
        logger.error(f"Validate invitation error {error_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "An error occurred", "error_id": error_id}), 500

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """Log out the current user by invalidating their session"""
    try:
        # Get session token from cookie
        session_token = session.get('auth_token')
        
        if session_token:
            # Invalidate session in database
            db = get_db()
            with db.get_connection() as conn:
                conn.execute(
                    "DELETE FROM sessions WHERE token = ?",
                    (session_token,)
                )
            
            # Clear session cookie
            session.pop('auth_token', None)
        
        return jsonify({"message": "Logged out successfully"})
    
    except Exception as e:
        monitor = get_monitor()
        error_id = monitor.log_error(e)
        logger.error(f"Logout error {error_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "An error occurred during logout", "error_id": error_id}), 500

@auth_bp.route('/user', methods=['GET'])
def get_current_user():
    """Get the current authenticated user"""
    try:
        # Check for authentication
        user = load_authenticated_user()
        
        if not user:
            return jsonify({"error": "Not authenticated"}), 401
        
        # Return user data
        return jsonify({"user": user})
    
    except Exception as e:
        monitor = get_monitor()
        error_id = monitor.log_error(e)
        logger.error(f"Get current user error {error_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "An error occurred", "error_id": error_id}), 500

@auth_bp.route('/change-password', methods=['POST'])
def change_password():
    """Change the user's password
    
    Request body:
    {
        "current_password": "current_password",
        "new_password": "new_password"
    }
    
    Returns:
        Success message
    """
    try:
        # Check for authentication
        user = load_authenticated_user()
        
        if not user:
            return jsonify({"error": "Not authenticated"}), 401
        
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        
        if not current_password or not new_password:
            return jsonify({"error": "Current password and new password are required"}), 400
        
        # Validate new password
        password_validation = validate_password(new_password)
        if not password_validation["valid"]:
            return jsonify({
                "error": "Password validation failed",
                "details": password_validation["errors"]
            }), 400
        
        # Verify current password
        db = get_db()
        stored_user = db.execute_query(
            "SELECT password_hash FROM users WHERE user_id = ?",
            (user["user_id"],),
            fetch_mode="one"
        )
        
        if not stored_user or not verify_password(current_password, stored_user["password_hash"]):
            return jsonify({"error": "Current password is incorrect"}), 401
        
        # Hash new password
        new_password_hash = hash_password(new_password)
        
        # Update password in database
        db.execute_query(
            "UPDATE users SET password_hash = ? WHERE user_id = ?",
            (new_password_hash, user["user_id"]),
            fetch_mode="none"
        )
        
        # Log password change
        logger.info(f"Password changed for user {user['username']} ({user['email']})")
        
        # Invalidate all existing sessions for security
        db.execute_query(
            "DELETE FROM sessions WHERE user_id = ?",
            (user["user_id"],),
            fetch_mode="none"
        )
        
        # Clear current session
        session.pop('auth_token', None)
        
        # Create new session
        request_info = {
            "ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", "")
        }
        
        # Create session token
        session_token = create_session(user["user_id"], request_info)
        
        # Store in HTTP-only cookie
        session['auth_token'] = session_token
        
        return jsonify({"message": "Password changed successfully"})
    
    except Exception as e:
        monitor = get_monitor()
        error_id = monitor.log_error(e)
        logger.error(f"Change password error {error_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "An error occurred", "error_id": error_id}), 500

@auth_bp.route('/refresh-token', methods=['POST'])
def refresh_token():
    """Refresh the JWT token
    
    Returns:
        New JWT token
    """
    try:
        # Check for authentication
        user = load_authenticated_user()
        
        if not user:
            return jsonify({"error": "Not authenticated"}), 401
        
        # Generate new JWT token
        jwt_token = generate_jwt_token(user["user_id"])
        
        return jsonify({
            "token": jwt_token,
            "message": "Token refreshed successfully"
        })
    
    except Exception as e:
        monitor = get_monitor()
        error_id = monitor.log_error(e)
        logger.error(f"Refresh token error {error_id}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "An error occurred", "error_id": error_id}), 500

# Helper functions
def hash_password(password: str) -> str:
    """Hash a password with bcrypt
    
    Args:
        password: Plain text password
        
    Returns:
        str: Hashed password
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against a hash
    
    Args:
        password: Plain text password
        password_hash: Hashed password
        
    Returns:
        bool: True if password matches hash
    """
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def generate_jwt_token(user_id: str, expires_in: int = 24) -> str:
    """Generate a JWT token for authentication
    
    Args:
        user_id: User ID
        expires_in: Token expiration in hours
        
    Returns:
        str: JWT token
    """
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=expires_in),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')

def verify_jwt_token(token: str) -> Optional[str]:
    """Verify a JWT token and return user_id if valid
    
    Args:
        token: JWT token
        
    Returns:
        Optional[str]: User ID if valid, None otherwise
    """
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload.get('user_id')
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def create_session(user_id: str, request_info: Optional[Dict[str, str]] = None) -> str:
    """Create a new session for the user
    
    Args:
        user_id: User ID
        request_info: Request information (IP, user agent)
        
    Returns:
        str: Session token
    """
    session_id = str(uuid.uuid4())
    token = secrets.token_urlsafe(64)
    expires_at = datetime.utcnow() + timedelta(days=30)
    
    ip_address = None
    user_agent = None
    
    if request_info:
        ip_address = request_info.get('ip')
        user_agent = request_info.get('user_agent')
    
    db = get_db()
    
    # Create session data
    session_data = {
        "session_id": session_id,
        "user_id": user_id,
        "token": token,
        "expires_at": expires_at.isoformat(),
        "ip_address": ip_address,
        "user_agent": user_agent
    }
    
    # Create session in database
    db.create_session(session_data)
    
    return token

def update_last_login(user_id: str) -> None:
    """Update the user's last login timestamp
    
    Args:
        user_id: User ID
    """
    db = get_db()
    db.execute_query(
        "UPDATE users SET last_login = ? WHERE user_id = ?",
        (datetime.utcnow().isoformat(), user_id),
        fetch_mode="none"
    )

def validate_invitation(token: str, email: str) -> Optional[Dict[str, Any]]:
    """Validate an invitation token for an email
    
    Args:
        token: Invitation token
        email: Email address
        
    Returns:
        Optional[Dict]: Invitation data if valid, None otherwise
    """
    db = get_db()
    
    # Look up invitation by token and email
    invitation = db.execute_query(
        """SELECT invitation_id, email, token, created_by, created_at, expires_at, used
        FROM invitations
        WHERE token = ? AND email = ? AND used = 0 AND expires_at > ?""",
        (token, email.lower(), datetime.utcnow().isoformat()),
        fetch_mode="one"
    )
    
    if not invitation:
        return None
    
    return dict(invitation)

def validate_password(password: str) -> Dict[str, Any]:
    """Validate password against security requirements
    
    Args:
        password: Password to validate
        
    Returns:
        Dict: Validation result
    """
    errors = []
    
    # Check against each pattern
    if not re.search(PASSWORD_PATTERNS["length"], password):
        errors.append("Password must be at least 8 characters long")
    
    if not re.search(PASSWORD_PATTERNS["uppercase"], password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not re.search(PASSWORD_PATTERNS["lowercase"], password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not re.search(PASSWORD_PATTERNS["digit"], password):
        errors.append("Password must contain at least one digit")
    
    if not re.search(PASSWORD_PATTERNS["special"], password):
        errors.append("Password must contain at least one special character")
    
    return {
        "valid": len(errors) == 0,
        "errors": errors
    }

def validate_registration_data(username: str, email: str, password: str) -> List[str]:
    """Validate user registration data
    
    Args:
        username: Username
        email: Email address
        password: Password
        
    Returns:
        List[str]: List of validation errors
    """
    errors = []
    
    # Validate username
    if not username:
        errors.append("Username is required")
    elif len(username) < 3:
        errors.append("Username must be at least 3 characters long")
    elif len(username) > 30:
        errors.append("Username must be at most 30 characters long")
    elif not re.match(r"^[a-zA-Z0-9_-]+$", username):
        errors.append("Username can only contain letters, numbers, underscores, and hyphens")
    
    # Validate email
    if not email:
        errors.append("Email is required")
    elif not re.match(EMAIL_REGEX, email):
        errors.append("Invalid email format")
    
    # Validate password
    password_validation = validate_password(password)
    if not password_validation["valid"]:
        errors.extend(password_validation["errors"])
    
    return errors

def load_authenticated_user() -> Optional[Dict[str, Any]]:
    """Load the authenticated user from session or token
    
    Returns:
        Optional[Dict]: User data if authenticated, None otherwise
    """
    # First check HTTP-only cookie session
    session_token = session.get('auth_token')
    if session_token:
        db = get_db()
        user_id = db.validate_session(session_token)
        if user_id:
            return db.get_user_by_id(user_id)
    
    # Then check Authorization header for JWT tokens (API usage)
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        user_id = verify_jwt_token(token)
        if user_id:
            db = get_db()
            return db.get_user_by_id(user_id)
    
    return None

# Authentication middleware for use in other blueprints
def login_required(f):
    """Decorator to require authentication for a route
    
    This can be exported and used in other blueprints
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = load_authenticated_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        
        # Set user in Flask's g object for the request
        g.user = user
        return f(*args, **kwargs)
    
    return decorated_function

# Register authentication middleware for before_request
@auth_bp.before_request
def load_user_from_session():
    """Load user before processing request"""
    # Clear any previous user
    g.user = None
    
    # Load user if authenticated
    user = load_authenticated_user()
    if user:
        g.user = user

# Register the blueprint with the Flask app
def register_blueprint(app):
    """Register the auth blueprint with the Flask app"""
    app.register_blueprint(auth_bp)
    logger.info("Auth routes registered")
